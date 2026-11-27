use std::time::Duration;

use futures::SinkExt;

use crate::{
	Role, WispError,
	packet::{CloseReason, ConnectPacket, MaybeInfoPacket, Packet, StreamType},
	stream::MuxStream,
	timer::{NoTimer, Timer},
	ws::{Payload, TransportRead, TransportReadExt, TransportWrite},
};

use super::{
	Multiplexor, MultiplexorImpl, MuxResult, WispHandshakeResult, WispHandshakeResultKind,
	WispV2Handshake, get_supported_extensions, handle_handshake,
	inner::{FlowControl, MultiplexorActor, StreamMap},
	missing_required_extensions, send_info_packet,
};

pub(crate) struct ServerActor {
	stream_tx: Option<flume::Sender<(ConnectPacket, MuxStream)>>,
}

impl MultiplexorActor for ServerActor {
	fn handle_connect_packet(
		&mut self,
		stream: MuxStream,
		pkt: ConnectPacket,
	) -> Result<(), WispError> {
		self.stream_tx
			.as_ref()
			.ok_or(WispError::MuxTaskEnded)?
			.send((pkt, stream))
			.map_err(|_| WispError::MuxMessageFailedToSend)
	}

	fn shutdown(&mut self) {
		self.stream_tx = None;
	}

	fn handle_data_packet(
		&mut self,
		id: u32,
		pkt: Payload,
		streams: &mut StreamMap,
	) -> Result<(), WispError> {
		if let Some(stream) = streams.get(&id)
			&& stream.stream.try_send(pkt).is_ok()
		{
			stream.info.flow_sub(1);
		}
		Ok(())
	}

	fn handle_continue_packet(
		&mut self,
		_: u32,
		_: crate::packet::ContinuePacket,
		_: &mut StreamMap,
	) -> Result<(), WispError> {
		Err(WispError::InvalidPacketType(0x03))
	}

	fn get_flow_control(ty: StreamType, flow_stream_types: &[u8]) -> FlowControl {
		if flow_stream_types.contains(&ty.into()) {
			FlowControl::EnabledSendMessages
		} else {
			FlowControl::Disabled
		}
	}
}

pub struct ServerImpl {
	buffer_size: u32,
	stream_rx: flume::Receiver<(ConnectPacket, MuxStream)>,
}

impl MultiplexorImpl for ServerImpl {
	type Actor = ServerActor;

	async fn handshake<R: TransportRead, W: TransportWrite>(
		&mut self,
		rx: &mut R,
		tx: &mut W,
		v2: Option<WispV2Handshake>,
		required: Vec<u8>,
	) -> Result<WispHandshakeResult, WispError> {
		if let Some(WispV2Handshake {
			mut builders,
			closure,
		}) = v2
		{
			send_info_packet(tx, &mut builders, Role::Server).await?;

			if let Some(closure) = closure {
				(closure)(&mut builders).await?;
			}

			let packet =
				MaybeInfoPacket::decode(rx.next_erroring().await?, &mut builders, Role::Server)?;

			match packet {
				MaybeInfoPacket::Info(info) => {
					if let Some(missing) =
						missing_required_extensions(Some(&info.extensions), required)
					{
						tx.send(Packet::new_close(0, CloseReason::ExtensionsIncompatible).encode())
							.await?;
						tx.close().await?;

						return Err(WispError::ExtensionsNotSupported(missing));
					}

					let mut supported_extensions =
						get_supported_extensions(info.extensions, &mut builders);

					if let Some((close_reason, err)) =
						handle_handshake(rx, tx, &mut supported_extensions).await?
					{
						tx.send(Packet::new_close(0, close_reason).encode()).await?;
						tx.close().await?;

						return Err(err);
					}

					tx.send(Packet::new_continue(0, self.buffer_size).encode())
						.await?;

					// v2 client
					Ok(WispHandshakeResult {
						kind: WispHandshakeResultKind::V2 {
							extensions: supported_extensions,
						},
						downgraded: false,
						buffer_size: self.buffer_size,
					})
				}
				MaybeInfoPacket::Packet(packet) => {
					if let Some(missing) = missing_required_extensions(None, required) {
						return Err(WispError::ExtensionsNotSupported(missing));
					}

					// downgrade to v1
					Ok(WispHandshakeResult {
						kind: WispHandshakeResultKind::V1 {
							packet: Some(packet),
						},
						downgraded: true,
						buffer_size: self.buffer_size,
					})
				}
			}
		} else {
			if let Some(missing) = missing_required_extensions(None, required) {
				return Err(WispError::ExtensionsNotSupported(missing));
			}

			// user asked for v1 server
			tx.send(Packet::new_continue(0, self.buffer_size).encode())
				.await?;

			Ok(WispHandshakeResult {
				kind: WispHandshakeResultKind::V1 { packet: None },
				downgraded: false,
				buffer_size: self.buffer_size,
			})
		}
	}
}

impl Multiplexor<ServerImpl> {
	/// Create a new server-side multiplexor.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created, otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You can specify the
	/// extensions you require to be supported in the `required_extensions` array.
	pub async fn new<R: TransportRead, W: TransportWrite>(
		rx: R,
		tx: W,
		buffer_size: u32,
		wisp_v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
	) -> Result<MuxResult<ServerImpl>, WispError> {
		let (stream_tx, stream_rx) = flume::unbounded();

		let mux = ServerImpl {
			buffer_size,
			stream_rx,
		};
		let actor = ServerActor {
			stream_tx: Some(stream_tx),
		};

		Self::create::<R, W, NoTimer>(rx, tx, wisp_v2, required_extensions, None, mux, actor).await
	}

	/// Create a new server-side multiplexor with a handshake timeout.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created, otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You can specify the
	/// extensions you require to be supported in the `required_extensions` array.
	pub async fn with_timeout<R: TransportRead, W: TransportWrite, T: Timer>(
		rx: R,
		tx: W,
		timer: T,
		timeout: Duration,
		buffer_size: u32,
		wisp_v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
	) -> Result<MuxResult<ServerImpl>, WispError> {
		let (stream_tx, stream_rx) = flume::unbounded();

		let mux = ServerImpl {
			buffer_size,
			stream_rx,
		};
		let actor = ServerActor {
			stream_tx: Some(stream_tx),
		};

		Self::create(
			rx,
			tx,
			wisp_v2,
			required_extensions,
			Some((timer, timeout)),
			mux,
			actor,
		)
		.await
	}

	/// Wait for a stream to be created.
	pub async fn wait_for_stream(&self) -> Option<(ConnectPacket, MuxStream)> {
		self.mux.stream_rx.recv_async().await.ok()
	}
}
