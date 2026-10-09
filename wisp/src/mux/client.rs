use std::time::Duration;

use futures::{channel::oneshot, SinkExt};

use crate::{
	extensions::udp::UdpProtocolExtension,
	mux::send_info_packet,
	packet::{CloseReason, ConnectPacket, ContinuePacket, MaybeInfoPacket, Packet, StreamType},
	stream::MuxStream,
	timer::{NoTimer, Timer},
	ws::{TransportRead, TransportReadExt, TransportWrite},
	LockedWebSocketWrite, Role, WispError,
};

use super::{
	get_supported_extensions, handle_handshake,
	inner::{FlowControl, MultiplexorActor, StreamMap, WsEvent},
	missing_required_extensions, validate_continue_packet, Multiplexor, MultiplexorImpl, MuxResult,
	WispHandshakeResult, WispHandshakeResultKind, WispV2Handshake,
};

pub(crate) struct ClientActor;

impl<W: TransportWrite> MultiplexorActor<W> for ClientActor {
	fn handle_connect_packet(
		&mut self,
		_: crate::stream::MuxStream<W>,
		_: crate::packet::ConnectPacket,
	) -> Result<(), WispError> {
		Err(WispError::InvalidPacketType(0x01))
	}

	fn handle_continue_packet(
		&mut self,
		id: u32,
		pkt: ContinuePacket,
		streams: &mut StreamMap,
	) -> Result<(), WispError> {
		if let Some(stream) = streams.get(&id) {
			if stream.info.flow_status == FlowControl::EnabledTrackAmount {
				stream.info.flow_set(pkt.buffer_remaining);
				stream.info.flow_wake();
			}
		}

		Ok(())
	}

	fn get_flow_control(ty: StreamType, flow_stream_types: &[u8]) -> FlowControl {
		if flow_stream_types.contains(&ty.into()) {
			FlowControl::EnabledTrackAmount
		} else {
			FlowControl::Disabled
		}
	}
}

pub struct ClientImpl;

impl<W: TransportWrite> MultiplexorImpl<W> for ClientImpl {
	type Actor = ClientActor;

	async fn handshake<R: TransportRead>(
		&mut self,
		rx: &mut R,
		tx: &mut LockedWebSocketWrite<W>,
		v2: Option<WispV2Handshake>,
		required: Vec<u8>,
	) -> Result<WispHandshakeResult, WispError> {
		if let Some(WispV2Handshake {
			mut builders,
			closure,
		}) = v2
		{
			// user asked for v2 client
			let packet =
				MaybeInfoPacket::decode(rx.next_erroring().await?, &mut builders, Role::Client)?;

			match packet {
				MaybeInfoPacket::Info(info) => {
					// v2 server
					
					if let Some(closure) = closure {
						(closure)(&mut builders).await?;
					}

					if let Some(missing) =
						missing_required_extensions(Some(&info.extensions), required)
					{
						tx.lock().await;
						let mut handle = tx.get_handle();
						handle
							.send(
								Packet::new_close(0, CloseReason::ExtensionsIncompatible).encode(),
							)
							.await?;
						handle.close().await?;

						return Err(WispError::ExtensionsNotSupported(missing));
					}

					let mut supported_extensions =
						get_supported_extensions(info.extensions, &mut builders);

					if let Some((close_reason, err)) =
						handle_handshake(rx, tx, &mut supported_extensions).await?
					{
						tx.lock().await;
						let mut handle = tx.get_handle();
						handle
							.send(Packet::new_close(0, close_reason).encode())
							.await?;
						handle.close().await?;

						return Err(err);
					}

					send_info_packet(tx, &mut builders, Role::Client).await?;

					let buffer_size =
						validate_continue_packet(&Packet::decode(rx.next_erroring().await?)?)?;

					Ok(WispHandshakeResult {
						kind: WispHandshakeResultKind::V2 {
							extensions: supported_extensions,
						},
						downgraded: false,
						buffer_size,
					})
				}
				MaybeInfoPacket::Packet(packet) => {
					// downgrade to v1
					let buffer_size = validate_continue_packet(&packet)?;

					if let Some(missing) = missing_required_extensions(None, required) {
						return Err(WispError::ExtensionsNotSupported(missing));
					}

					Ok(WispHandshakeResult {
						kind: WispHandshakeResultKind::V1 { packet: None },
						downgraded: true,
						buffer_size,
					})
				}
			}
		} else {
			if let Some(missing) = missing_required_extensions(None, required) {
				return Err(WispError::ExtensionsNotSupported(missing));
			}

			// user asked for a v1 client
			let buffer_size =
				validate_continue_packet(&Packet::decode(rx.next_erroring().await?)?)?;

			Ok(WispHandshakeResult {
				kind: WispHandshakeResultKind::V1 { packet: None },
				downgraded: false,
				buffer_size,
			})
		}
	}
}

impl<W: TransportWrite> Multiplexor<ClientImpl, W> {
	/// Create a new client side multiplexor.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created, otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You can specify the
	/// extensions you require to be supported in the `required_extensions` array.
	pub async fn new<R: TransportRead>(
		rx: R,
		tx: W,
		wisp_v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
	) -> Result<MuxResult<ClientImpl, W>, WispError> {
		Self::create::<R, NoTimer>(
			rx,
			tx,
			wisp_v2,
			required_extensions,
			None,
			ClientImpl,
			ClientActor,
		)
		.await
	}

	/// Create a new client side multiplexor with a handshake timeout.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created, otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You can specify the
	/// extensions you require to be supported in the `required_extensions` array.
	pub async fn with_timeout<R: TransportRead, T: Timer>(
		rx: R,
		tx: W,
		timer: T,
		timeout: Duration,
		wisp_v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
	) -> Result<MuxResult<ClientImpl, W>, WispError> {
		Self::create(
			rx,
			tx,
			wisp_v2,
			required_extensions,
			Some((timer, timeout)),
			ClientImpl,
			ClientActor,
		)
		.await
	}

	/// Create a new stream, multiplexed through Wisp.
	pub async fn new_stream(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> Result<MuxStream<W>, WispError> {
		if self.actor_tx.is_disconnected() {
			return Err(WispError::MuxTaskEnded);
		}

		if stream_type == StreamType::Udp
			&& !self
				.supported_extensions
				.iter()
				.any(|x| x.get_id() == UdpProtocolExtension::ID)
		{
			return Err(WispError::ExtensionsNotSupported(vec![
				UdpProtocolExtension::ID,
			]));
		}

		let (tx, rx) = oneshot::channel();
		self.actor_tx
			.send_async(WsEvent::CreateStream(
				ConnectPacket {
					stream_type,
					host,
					port,
				},
				tx,
			))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)?
	}
}
