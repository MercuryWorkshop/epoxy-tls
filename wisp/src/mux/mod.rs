mod client;
pub(crate) mod inner;
mod server;
use std::{
	future::Future,
	pin::{pin, Pin},
	time::Duration,
};

use futures::{
	future::{select, Either},
	SinkExt,
};
use inner::{MultiplexorActor, MuxInner, WsEvent};

pub use client::ClientImpl;
pub use server::ServerImpl;

pub type ServerMux<W> = Multiplexor<ServerImpl<W>, W>;
pub type ClientMux<W> = Multiplexor<ClientImpl, W>;

use crate::{
	extensions::{udp::UdpProtocolExtension, AnyProtocolExtension, AnyProtocolExtensionBuilder},
	inner::MuxInnerResult,
	packet::{CloseReason, InfoPacket, Packet, PacketType},
	timer::Timer,
	ws::{TransportRead, TransportWrite},
	LockedWebSocketWrite, LockedWebSocketWriteGuard, Role, WispError, WISP_VERSION,
};

struct WispHandshakeResult {
	kind: WispHandshakeResultKind,
	downgraded: bool,
	buffer_size: u32,
}

enum WispHandshakeResultKind {
	V2 {
		extensions: Vec<AnyProtocolExtension>,
	},
	V1 {
		packet: Option<Packet<'static>>,
	},
}

impl WispHandshakeResultKind {
	pub fn into_parts(self) -> (Vec<AnyProtocolExtension>, Option<Packet<'static>>) {
		match self {
			Self::V2 { extensions } => (extensions, None),
			Self::V1 { packet } => (vec![UdpProtocolExtension.into()], packet),
		}
	}
}

async fn handle_handshake<R: TransportRead, W: TransportWrite>(
	read: &mut R,
	write: &mut LockedWebSocketWrite<W>,
	extensions: &mut [AnyProtocolExtension],
) -> Result<Option<(CloseReason, WispError)>, WispError> {
	write.lock().await;
	let mut handle = write.get_handle();
	for extension in extensions {
		if let Some(reason) = extension.handle_handshake(read, &mut handle).await? {
			return Ok(Some(reason));
		}
	}
	drop(handle);

	Ok(None)
}

async fn send_info_packet<W: TransportWrite>(
	write: &mut LockedWebSocketWrite<W>,
	builders: &mut [AnyProtocolExtensionBuilder],
	role: Role,
) -> Result<(), WispError> {
	let extensions = builders
		.iter_mut()
		.map(|x| x.build_to_extension(role))
		.collect::<Result<Vec<_>, _>>()?;

	let packet = InfoPacket {
		version: WISP_VERSION,
		extensions,
	}
	.encode();

	write.lock().await;
	let ret = write.get().send(packet).await;
	write.unlock();

	ret
}

fn validate_continue_packet(packet: &Packet) -> Result<u32, WispError> {
	if packet.stream_id != 0 {
		return Err(WispError::InvalidStreamId(packet.stream_id));
	}

	let PacketType::Continue(continue_packet) = packet.packet_type else {
		return Err(WispError::InvalidPacketType(packet.packet_type.get_type()));
	};

	Ok(continue_packet.buffer_remaining)
}

fn get_supported_extensions(
	extensions: Vec<AnyProtocolExtension>,
	builders: &mut [AnyProtocolExtensionBuilder],
) -> Vec<AnyProtocolExtension> {
	let extension_ids: Vec<_> = builders.iter().map(|x| x.get_id()).collect();
	extensions
		.into_iter()
		.filter(|x| extension_ids.contains(&x.get_id()))
		.collect()
}

fn missing_required_extensions(
	extensions: Option<&[AnyProtocolExtension]>,
	required: Vec<u8>,
) -> Option<Vec<u8>> {
	let ids: Vec<u8> = extensions
		.map(|x| x.iter().map(|x| x.get_id()).collect())
		.unwrap_or_else(|| vec![UdpProtocolExtension::ID]);
	let missing: Vec<u8> = required.into_iter().filter(|x| !ids.contains(x)).collect();
	(!missing.is_empty()).then_some(missing)
}

trait MultiplexorImpl<W: TransportWrite> {
	type Actor: MultiplexorActor<W> + 'static;

	async fn handshake<R: TransportRead>(
		&mut self,
		rx: &mut R,
		tx: &mut LockedWebSocketWrite<W>,
		v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
	) -> Result<WispHandshakeResult, WispError>;
}

#[expect(private_bounds)]
pub struct Multiplexor<M: MultiplexorImpl<W>, W: TransportWrite> {
	mux: M,

	downgraded: bool,
	supported_extensions: Vec<AnyProtocolExtension>,

	actor_tx: flume::Sender<WsEvent<W>>,
	tx: LockedWebSocketWrite<W>,
}

#[expect(private_bounds)]
impl<M: MultiplexorImpl<W>, W: TransportWrite> Multiplexor<M, W> {
	async fn create<R, T>(
		mut rx: R,
		tx: W,
		wisp_v2: Option<WispV2Handshake>,
		required_extensions: Vec<u8>,
		timer: Option<(T, Duration)>,
		mut muxer: M,
		actor: M::Actor,
	) -> Result<MuxResult<M, W>, WispError>
	where
		R: TransportRead,
		T: Timer,
	{
		let mut tx = LockedWebSocketWrite::new(tx);
		let handshake_result = if let Some((mut timer, duration)) = timer {
			match select(
				pin!(muxer.handshake(&mut rx, &mut tx, wisp_v2, required_extensions)),
				pin!(timer.sleep(duration)),
			)
			.await
			{
				Either::Left((ret, _)) => ret?,
				Either::Right(_) => return Err(WispError::HandshakeTimedOut),
			}
		} else {
			muxer
				.handshake(&mut rx, &mut tx, wisp_v2, required_extensions)
				.await?
		};
		let (extensions, extra_packet) = handshake_result.kind.into_parts();

		let MuxInnerResult { mux, actor_tx } = MuxInner::new(
			rx,
			tx.clone(),
			actor,
			extra_packet,
			extensions.clone(),
			handshake_result.buffer_size,
		);

		Ok((
			Self {
				mux: muxer,

				downgraded: handshake_result.downgraded,
				supported_extensions: extensions,

				actor_tx,
				tx,
			},
			Box::pin(mux.into_future()),
		))
	}

	/// Whether the connection was downgraded to Wisp v1.
	pub fn was_downgraded(&self) -> bool {
		self.downgraded
	}

	/// Get a shared reference to the extensions that are supported by both sides.
	pub fn get_extensions(&self) -> &[AnyProtocolExtension] {
		&self.supported_extensions
	}

	/// Get a mutable reference to the extensions that are supported by both sides.
	pub fn get_extensions_mut(&mut self) -> &mut [AnyProtocolExtension] {
		&mut self.supported_extensions
	}

	/// Get a `Vec` of all extension IDs that are supported by both sides.
	pub fn get_extension_ids(&self) -> Vec<u8> {
		self.supported_extensions
			.iter()
			.map(|x| x.get_id())
			.collect()
	}

	/// Get a locked guard to the write half of the websocket.
	pub async fn lock_ws(&self) -> Result<LockedWebSocketWriteGuard<W>, WispError> {
		if self.actor_tx.is_disconnected() {
			Err(WispError::WsImplSocketClosed)
		} else {
			let mut cloned = self.tx.clone();
			cloned.lock().await;
			Ok(cloned.get_guard())
		}
	}

	async fn close_internal(&self, reason: Option<CloseReason>) -> Result<(), WispError> {
		self.actor_tx
			.send_async(WsEvent::EndFut(reason))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)
	}

	/// Close all streams.
	///
	/// Also terminates the multiplexor future.
	pub async fn close(&self) -> Result<(), WispError> {
		self.close_internal(None).await
	}

	/// Close all streams and send a close reason on stream ID 0.
	///
	/// Also terminates the multiplexor future.
	pub async fn close_with_reason(&self, reason: CloseReason) -> Result<(), WispError> {
		self.close_internal(Some(reason)).await
	}

	/* TODO
	/// Get a protocol extension stream for sending packets with stream id 0.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream<W> {
		MuxProtocolExtensionStream {
			stream_id: 0,
			tx: self.tx.clone(),
			is_closed: self.actor_exited.clone(),
		}
	}
	*/
}

pub type MultiplexorActorFuture = Pin<Box<dyn Future<Output = Result<(), WispError>> + Send>>;

/// Result of creating a multiplexor. Helps require protocol extensions.
#[expect(private_bounds, type_alias_bounds)]
pub type MuxResult<M: MultiplexorImpl<W>, W: TransportWrite> =
	(Multiplexor<M, W>, MultiplexorActorFuture);

/// Wisp V2 middleware closure.
pub type WispV2Middleware = dyn for<'a> Fn(
		&'a mut Vec<AnyProtocolExtensionBuilder>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Sync + Send + 'a>>
	+ Send;
/// Wisp V2 handshake and protocol extension settings wrapper struct.
pub struct WispV2Handshake {
	builders: Vec<AnyProtocolExtensionBuilder>,
	closure: Option<Box<WispV2Middleware>>,
}

impl WispV2Handshake {
	/// Create a Wisp V2 settings struct with no extensions
	pub fn empty() -> Self {
		Self {
			builders: Vec::new(),
			closure: None,
		}
	}

	/// Create a Wisp V2 settings struct with some extensions.
	pub fn new(builders: Vec<AnyProtocolExtensionBuilder>) -> Self {
		Self {
			builders,
			closure: None,
		}
	}

	/// Add some middleware to the settings struct.
	pub fn with_middleware(mut self, closure: Box<WispV2Middleware>) -> Self {
		self.closure.replace(closure);

		self
	}

	/// Add a Wisp V2 extension builder to the settings struct.
	pub fn with_extension(mut self, extension: AnyProtocolExtensionBuilder) -> Self {
		self.builders.push(extension);

		self
	}
}
