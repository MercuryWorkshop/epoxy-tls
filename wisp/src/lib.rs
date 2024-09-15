#![deny(missing_docs, clippy::todo)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A library for easily creating [Wisp] clients and servers.
//!
//! [Wisp]: https://github.com/MercuryWorkshop/wisp-protocol

pub mod extensions;
#[cfg(feature = "fastwebsockets")]
#[cfg_attr(docsrs, doc(cfg(feature = "fastwebsockets")))]
mod fastwebsockets;
#[cfg(feature = "generic_stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "generic_stream")))]
pub mod generic;
mod inner;
mod packet;
mod sink_unfold;
mod stream;
pub mod ws;

pub use crate::{packet::*, stream::*};

use extensions::{udp::UdpProtocolExtension, AnyProtocolExtension, ProtocolExtensionBuilder};
use flume as mpsc;
use futures::{channel::oneshot, select, Future, FutureExt};
use futures_timer::Delay;
use inner::{MuxInner, WsEvent};
use std::{
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};
use ws::{AppendingWebSocketRead, LockedWebSocketWrite};

/// Wisp version supported by this crate.
pub const WISP_VERSION: WispVersion = WispVersion { major: 2, minor: 0 };

/// The role of the multiplexor.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
	/// Client side, can create new channels to proxy.
	Client,
	/// Server side, can listen for channels to proxy.
	Server,
}

/// Errors the Wisp implementation can return.
#[derive(Debug)]
pub enum WispError {
	/// The packet received did not have enough data.
	PacketTooSmall,
	/// The packet received had an invalid type.
	InvalidPacketType,
	/// The stream had an invalid ID.
	InvalidStreamId,
	/// The close packet had an invalid reason.
	InvalidCloseReason,
	/// The URI received was invalid.
	InvalidUri,
	/// The URI received had no host.
	UriHasNoHost,
	/// The URI received had no port.
	UriHasNoPort,
	/// The max stream count was reached.
	MaxStreamCountReached,
	/// The Wisp protocol version was incompatible.
	IncompatibleProtocolVersion,
	/// The stream had already been closed.
	StreamAlreadyClosed,

	/// The websocket frame received had an invalid type.
	WsFrameInvalidType,
	/// The websocket frame received was not finished.
	WsFrameNotFinished,
	/// Error specific to the websocket implementation.
	WsImplError(Box<dyn std::error::Error + Sync + Send>),
	/// The websocket implementation socket closed.
	WsImplSocketClosed,
	/// The websocket implementation did not support the action.
	WsImplNotSupported,

	/// The string was invalid UTF-8.
	Utf8Error(std::str::Utf8Error),
	/// The integer failed to convert.
	TryFromIntError(std::num::TryFromIntError),
	/// Other error.
	Other(Box<dyn std::error::Error + Sync + Send>),

	/// Failed to send message to multiplexor task.
	MuxMessageFailedToSend,
	/// Failed to receive message from multiplexor task.
	MuxMessageFailedToRecv,
	/// Multiplexor task ended.
	MuxTaskEnded,
	/// Multiplexor task already started.
	MuxTaskStarted,

	/// Error specific to the protocol extension implementation.
	ExtensionImplError(Box<dyn std::error::Error + Sync + Send>),
	/// The protocol extension implementation did not support the action.
	ExtensionImplNotSupported,
	/// The specified protocol extensions are not supported by the server.
	ExtensionsNotSupported(Vec<u8>),
	/// The password authentication username/password was invalid.
	PasswordExtensionCredsInvalid,
	/// The certificate authentication signature was invalid.
	CertAuthExtensionSigInvalid,
}

impl From<std::str::Utf8Error> for WispError {
	fn from(err: std::str::Utf8Error) -> Self {
		Self::Utf8Error(err)
	}
}

impl From<std::num::TryFromIntError> for WispError {
	fn from(value: std::num::TryFromIntError) -> Self {
		Self::TryFromIntError(value)
	}
}

impl std::fmt::Display for WispError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		match self {
			Self::PacketTooSmall => write!(f, "Packet too small"),
			Self::InvalidPacketType => write!(f, "Invalid packet type"),
			Self::InvalidStreamId => write!(f, "Invalid stream id"),
			Self::InvalidCloseReason => write!(f, "Invalid close reason"),
			Self::InvalidUri => write!(f, "Invalid URI"),
			Self::UriHasNoHost => write!(f, "URI has no host"),
			Self::UriHasNoPort => write!(f, "URI has no port"),
			Self::MaxStreamCountReached => write!(f, "Maximum stream count reached"),
			Self::IncompatibleProtocolVersion => write!(f, "Incompatible Wisp protocol version"),
			Self::StreamAlreadyClosed => write!(f, "Stream already closed"),
			Self::WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
			Self::WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
			Self::WsImplError(err) => write!(f, "Websocket implementation error: {}", err),
			Self::WsImplSocketClosed => {
				write!(f, "Websocket implementation error: websocket closed")
			}
			Self::WsImplNotSupported => {
				write!(f, "Websocket implementation error: unsupported feature")
			}
			Self::ExtensionImplError(err) => {
				write!(f, "Protocol extension implementation error: {}", err)
			}
			Self::ExtensionImplNotSupported => {
				write!(
					f,
					"Protocol extension implementation error: unsupported feature"
				)
			}
			Self::ExtensionsNotSupported(list) => {
				write!(f, "Protocol extensions {:?} not supported", list)
			}
			Self::Utf8Error(err) => write!(f, "UTF-8 error: {}", err),
			Self::TryFromIntError(err) => write!(f, "Integer conversion error: {}", err),
			Self::Other(err) => write!(f, "Other error: {}", err),
			Self::MuxMessageFailedToSend => write!(f, "Failed to send multiplexor message"),
			Self::MuxMessageFailedToRecv => write!(f, "Failed to receive multiplexor message"),
			Self::MuxTaskEnded => write!(f, "Multiplexor task ended"),
			Self::MuxTaskStarted => write!(f, "Multiplexor task already started"),
			Self::PasswordExtensionCredsInvalid => {
				write!(f, "Password extension: Invalid username/password")
			}
			Self::CertAuthExtensionSigInvalid => {
				write!(f, "Certificate authentication extension: Invalid signature")
			}
		}
	}
}

impl std::error::Error for WispError {}

async fn maybe_wisp_v2<R>(
	read: &mut R,
	write: &LockedWebSocketWrite,
	builders: &mut [Box<dyn ProtocolExtensionBuilder + Sync + Send>],
) -> Result<(Vec<AnyProtocolExtension>, Option<ws::Frame<'static>>, bool), WispError>
where
	R: ws::WebSocketRead + Send,
{
	let mut supported_extensions = Vec::new();
	let mut extra_packet: Option<ws::Frame<'static>> = None;
	let mut downgraded = true;

	let extension_ids: Vec<_> = builders.iter().map(|x| x.get_id()).collect();
	if let Some(frame) = select! {
		x = read.wisp_read_frame(write).fuse() => Some(x?),
		_ = Delay::new(Duration::from_secs(5)).fuse() => None
	} {
		let packet = Packet::maybe_parse_info(frame, Role::Client, builders)?;
		if let PacketType::Info(info) = packet.packet_type {
			supported_extensions = info
				.extensions
				.into_iter()
				.filter(|x| extension_ids.contains(&x.get_id()))
				.collect();
			downgraded = false;
		} else {
			extra_packet.replace(ws::Frame::from(packet).clone());
		}
	}

	for extension in supported_extensions.iter_mut() {
		extension.handle_handshake(read, write).await?;
	}
	Ok((supported_extensions, extra_packet, downgraded))
}

async fn send_info_packet(
	write: &LockedWebSocketWrite,
	builders: &mut [Box<dyn ProtocolExtensionBuilder + Sync + Send>],
) -> Result<(), WispError> {
	write
		.write_frame(
			Packet::new_info(
				builders
					.iter_mut()
					.map(|x| x.build_to_extension(Role::Server))
					.collect::<Result<Vec<_>, _>>()?,
			)
			.into(),
		)
		.await
}

/// Server-side multiplexor.
pub struct ServerMux {
	/// Whether the connection was downgraded to Wisp v1.
	///
	/// If this variable is true you must assume no extensions are supported.
	pub downgraded: bool,
	/// Extensions that are supported by both sides.
	pub supported_extensions: Vec<AnyProtocolExtension>,
	actor_tx: mpsc::Sender<WsEvent>,
	muxstream_recv: mpsc::Receiver<(ConnectPacket, MuxStream)>,
	tx: ws::LockedWebSocketWrite,
	actor_exited: Arc<AtomicBool>,
}

impl ServerMux {
	/// Create a new server-side multiplexor.
	///
	/// If `extension_builders` is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You must manually check
	/// if the extensions you need are available after the multiplexor has been created.
	pub async fn create<R, W>(
		mut rx: R,
		tx: W,
		buffer_size: u32,
		extension_builders: Option<Vec<Box<dyn ProtocolExtensionBuilder + Send + Sync>>>,
	) -> Result<ServerMuxResult<impl Future<Output = Result<(), WispError>> + Send>, WispError>
	where
		R: ws::WebSocketRead + Send,
		W: ws::WebSocketWrite + Send + 'static,
	{
		let tx = ws::LockedWebSocketWrite::new(Box::new(tx));
		let ret_tx = tx.clone();
		let ret = async {
			tx.write_frame(Packet::new_continue(0, buffer_size).into())
				.await?;

			let (supported_extensions, extra_packet, downgraded) =
				if let Some(mut builders) = extension_builders {
					send_info_packet(&tx, &mut builders).await?;
					maybe_wisp_v2(&mut rx, &tx, &mut builders).await?
				} else {
					(Vec::new(), None, true)
				};

			let (mux_result, muxstream_recv) = MuxInner::new_server(
				AppendingWebSocketRead(extra_packet, rx),
				tx.clone(),
				supported_extensions.clone(),
				buffer_size,
			);

			Ok(ServerMuxResult(
				Self {
					muxstream_recv,
					actor_tx: mux_result.actor_tx,
					downgraded,
					supported_extensions,
					tx,
					actor_exited: mux_result.actor_exited,
				},
				mux_result.mux.into_future(),
			))
		}
		.await;

		match ret {
			Ok(x) => Ok(x),
			Err(x) => match x {
				WispError::PasswordExtensionCredsInvalid => {
					ret_tx
						.write_frame(
							Packet::new_close(0, CloseReason::ExtensionsPasswordAuthFailed).into(),
						)
						.await?;
					ret_tx.close().await?;
					Err(x)
				}
				WispError::CertAuthExtensionSigInvalid => {
					ret_tx
						.write_frame(
							Packet::new_close(0, CloseReason::ExtensionsCertAuthFailed).into(),
						)
						.await?;
					ret_tx.close().await?;
					Err(x)
				}
				x => Err(x),
			},
		}
	}

	/// Wait for a stream to be created.
	pub async fn server_new_stream(&self) -> Option<(ConnectPacket, MuxStream)> {
		if self.actor_exited.load(Ordering::Acquire) {
			return None;
		}
		self.muxstream_recv.recv_async().await.ok()
	}

	async fn close_internal(&self, reason: Option<CloseReason>) -> Result<(), WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
			return Err(WispError::MuxTaskEnded);
		}
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

	/// Get a protocol extension stream for sending packets with stream id 0.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream {
		MuxProtocolExtensionStream {
			stream_id: 0,
			tx: self.tx.clone(),
			is_closed: self.actor_exited.clone(),
		}
	}
}

impl Drop for ServerMux {
	fn drop(&mut self) {
		let _ = self.actor_tx.send(WsEvent::EndFut(None));
	}
}

/// Result of `ServerMux::new`.
pub struct ServerMuxResult<F>(ServerMux, F)
where
	F: Future<Output = Result<(), WispError>> + Send;

impl<F> ServerMuxResult<F>
where
	F: Future<Output = Result<(), WispError>> + Send,
{
	/// Require no protocol extensions.
	pub fn with_no_required_extensions(self) -> (ServerMux, F) {
		(self.0, self.1)
	}

	/// Require protocol extensions by their ID. Will close the multiplexor connection if
	/// extensions are not supported.
	pub async fn with_required_extensions(
		self,
		extensions: &[u8],
	) -> Result<(ServerMux, F), WispError> {
		let mut unsupported_extensions = Vec::new();
		for extension in extensions {
			if !self
				.0
				.supported_extensions
				.iter()
				.any(|x| x.get_id() == *extension)
			{
				unsupported_extensions.push(*extension);
			}
		}
		if unsupported_extensions.is_empty() {
			Ok((self.0, self.1))
		} else {
			self.0
				.close_with_reason(CloseReason::ExtensionsIncompatible)
				.await?;
			self.1.await?;
			Err(WispError::ExtensionsNotSupported(unsupported_extensions))
		}
	}

	/// Shorthand for `with_required_extensions(&[UdpProtocolExtension::ID])`
	pub async fn with_udp_extension_required(self) -> Result<(ServerMux, F), WispError> {
		self.with_required_extensions(&[UdpProtocolExtension::ID])
			.await
	}
}

/// Client side multiplexor.
pub struct ClientMux {
	/// Whether the connection was downgraded to Wisp v1.
	///
	/// If this variable is true you must assume no extensions are supported.
	pub downgraded: bool,
	/// Extensions that are supported by both sides.
	pub supported_extensions: Vec<AnyProtocolExtension>,
	actor_tx: mpsc::Sender<WsEvent>,
	tx: ws::LockedWebSocketWrite,
	actor_exited: Arc<AtomicBool>,
}

impl ClientMux {
	/// Create a new client side multiplexor.
	///
	/// If `extension_builders` is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You must manually check
	/// if the extensions you need are available after the multiplexor has been created.
	pub async fn create<R, W>(
		mut rx: R,
		tx: W,
		extension_builders: Option<Vec<Box<dyn ProtocolExtensionBuilder + Send + Sync>>>,
	) -> Result<ClientMuxResult<impl Future<Output = Result<(), WispError>> + Send>, WispError>
	where
		R: ws::WebSocketRead + Send,
		W: ws::WebSocketWrite + Send + 'static,
	{
		let tx = ws::LockedWebSocketWrite::new(Box::new(tx));
		let first_packet = Packet::try_from(rx.wisp_read_frame(&tx).await?)?;

		if first_packet.stream_id != 0 {
			return Err(WispError::InvalidStreamId);
		}

		if let PacketType::Continue(packet) = first_packet.packet_type {
			let (supported_extensions, extra_packet, downgraded) =
				if let Some(mut builders) = extension_builders {
					let res = maybe_wisp_v2(&mut rx, &tx, &mut builders).await?;
					// if not downgraded
					if !res.2 {
						send_info_packet(&tx, &mut builders).await?;
					}
					res
				} else {
					(Vec::new(), None, true)
				};

			let mux_result = MuxInner::new_client(
				AppendingWebSocketRead(extra_packet, rx),
				tx.clone(),
				supported_extensions.clone(),
				packet.buffer_remaining,
			);

			Ok(ClientMuxResult(
				Self {
					actor_tx: mux_result.actor_tx,
					downgraded,
					supported_extensions,
					tx,
					actor_exited: mux_result.actor_exited,
				},
				mux_result.mux.into_future(),
			))
		} else {
			Err(WispError::InvalidPacketType)
		}
	}

	/// Create a new stream, multiplexed through Wisp.
	pub async fn client_new_stream(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> Result<MuxStream, WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
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
			.send_async(WsEvent::CreateStream(stream_type, host, port, tx))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)?
	}

	async fn close_internal(&self, reason: Option<CloseReason>) -> Result<(), WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
			return Err(WispError::MuxTaskEnded);
		}
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

	/// Get a protocol extension stream for sending packets with stream id 0.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream {
		MuxProtocolExtensionStream {
			stream_id: 0,
			tx: self.tx.clone(),
			is_closed: self.actor_exited.clone(),
		}
	}
}

impl Drop for ClientMux {
	fn drop(&mut self) {
		let _ = self.actor_tx.send(WsEvent::EndFut(None));
	}
}

/// Result of `ClientMux::new`.
pub struct ClientMuxResult<F>(ClientMux, F)
where
	F: Future<Output = Result<(), WispError>> + Send;

impl<F> ClientMuxResult<F>
where
	F: Future<Output = Result<(), WispError>> + Send,
{
	/// Require no protocol extensions.
	pub fn with_no_required_extensions(self) -> (ClientMux, F) {
		(self.0, self.1)
	}

	/// Require protocol extensions by their ID.
	pub async fn with_required_extensions(
		self,
		extensions: &[u8],
	) -> Result<(ClientMux, F), WispError> {
		let mut unsupported_extensions = Vec::new();
		for extension in extensions {
			if !self
				.0
				.supported_extensions
				.iter()
				.any(|x| x.get_id() == *extension)
			{
				unsupported_extensions.push(*extension);
			}
		}
		if unsupported_extensions.is_empty() {
			Ok((self.0, self.1))
		} else {
			self.0
				.close_with_reason(CloseReason::ExtensionsIncompatible)
				.await?;
			self.1.await?;
			Err(WispError::ExtensionsNotSupported(unsupported_extensions))
		}
	}

	/// Shorthand for `with_required_extensions(&[UdpProtocolExtension::ID])`
	pub async fn with_udp_extension_required(self) -> Result<(ClientMux, F), WispError> {
		self.with_required_extensions(&[UdpProtocolExtension::ID])
			.await
	}
}
