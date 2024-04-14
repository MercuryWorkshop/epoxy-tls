#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A library for easily creating [Wisp] clients and servers.
//!
//! [Wisp]: https://github.com/MercuryWorkshop/wisp-protocol

pub mod extensions;
#[cfg(feature = "fastwebsockets")]
#[cfg_attr(docsrs, doc(cfg(feature = "fastwebsockets")))]
mod fastwebsockets;
mod packet;
mod sink_unfold;
mod stream;
pub mod ws;

pub use crate::{packet::*, stream::*};

use bytes::Bytes;
use dashmap::DashMap;
use event_listener::Event;
use extensions::{udp::UdpProtocolExtension, AnyProtocolExtension, ProtocolExtensionBuilder};
use futures::{
    channel::{mpsc, oneshot},
    select, Future, FutureExt, SinkExt, StreamExt,
};
use futures_timer::Delay;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use ws::AppendingWebSocketRead;

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
    /// Error specific to the protocol extension implementation.
    ExtensionImplError(Box<dyn std::error::Error + Sync + Send>),
    /// The protocol extension implementation did not support the action.
    ExtensionImplNotSupported,
    /// The UDP protocol extension is not supported by the server.
    UdpExtensionNotSupported,
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
            Self::UdpExtensionNotSupported => write!(f, "UDP protocol extension not supported"),
            Self::Utf8Error(err) => write!(f, "UTF-8 error: {}", err),
            Self::TryFromIntError(err) => write!(f, "Integer conversion error: {}", err),
            Self::Other(err) => write!(f, "Other error: {}", err),
            Self::MuxMessageFailedToSend => write!(f, "Failed to send multiplexor message"),
            Self::MuxMessageFailedToRecv => write!(f, "Failed to receive multiplexor message"),
        }
    }
}

impl std::error::Error for WispError {}

struct MuxMapValue {
    stream: mpsc::UnboundedSender<Bytes>,
    stream_type: StreamType,
    flow_control: Arc<AtomicU32>,
    flow_control_event: Arc<Event>,
    is_closed: Arc<AtomicBool>,
}

struct MuxInner {
    tx: ws::LockedWebSocketWrite,
    stream_map: DashMap<u32, MuxMapValue>,
    buffer_size: u32,
}

impl MuxInner {
    pub async fn server_into_future<R>(
        self,
        rx: R,
        extensions: Vec<AnyProtocolExtension>,
        close_rx: mpsc::Receiver<WsEvent>,
        muxstream_sender: mpsc::UnboundedSender<(ConnectPacket, MuxStream)>,
        close_tx: mpsc::Sender<WsEvent>,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead + Send,
    {
        self.as_future(
            close_rx,
            close_tx.clone(),
            self.server_loop(rx, extensions, muxstream_sender, close_tx),
        )
        .await
    }

    pub async fn client_into_future<R>(
        self,
        rx: R,
        extensions: Vec<AnyProtocolExtension>,
        close_rx: mpsc::Receiver<WsEvent>,
        close_tx: mpsc::Sender<WsEvent>,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead + Send,
    {
        self.as_future(close_rx, close_tx, self.client_loop(rx, extensions))
            .await
    }

    async fn as_future(
        &self,
        close_rx: mpsc::Receiver<WsEvent>,
        close_tx: mpsc::Sender<WsEvent>,
        wisp_fut: impl Future<Output = Result<(), WispError>>,
    ) -> Result<(), WispError> {
        let ret = futures::select! {
            _ = self.stream_loop(close_rx, close_tx).fuse() => Ok(()),
            x = wisp_fut.fuse() => x,
        };
        self.stream_map.iter_mut().for_each(|mut x| {
            x.is_closed.store(true, Ordering::Release);
            x.stream.disconnect();
            x.stream.close_channel();
        });
        self.stream_map.clear();
        ret
    }

    async fn stream_loop(
        &self,
        mut stream_rx: mpsc::Receiver<WsEvent>,
        stream_tx: mpsc::Sender<WsEvent>,
    ) {
        let mut next_free_stream_id: u32 = 1;
        while let Some(msg) = stream_rx.next().await {
            match msg {
                WsEvent::SendPacket(packet, channel) => {
                    if self.stream_map.get(&packet.stream_id).is_some() {
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::CreateStream(stream_type, host, port, channel) => {
                    let ret: Result<MuxStream, WispError> = async {
                        let (ch_tx, ch_rx) = mpsc::unbounded();
                        let stream_id = next_free_stream_id;
                        let next_stream_id = next_free_stream_id
                            .checked_add(1)
                            .ok_or(WispError::MaxStreamCountReached)?;

                        let flow_control_event: Arc<Event> = Event::new().into();
                        let flow_control: Arc<AtomicU32> = AtomicU32::new(self.buffer_size).into();

                        let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();

                        self.tx
                            .write_frame(
                                Packet::new_connect(stream_id, stream_type, port, host).into(),
                            )
                            .await?;

                        next_free_stream_id = next_stream_id;

                        self.stream_map.insert(
                            stream_id,
                            MuxMapValue {
                                stream: ch_tx,
                                stream_type,
                                flow_control: flow_control.clone(),
                                flow_control_event: flow_control_event.clone(),
                                is_closed: is_closed.clone(),
                            },
                        );

                        Ok(MuxStream::new(
                            stream_id,
                            Role::Client,
                            stream_type,
                            ch_rx,
                            stream_tx.clone(),
                            is_closed,
                            flow_control,
                            flow_control_event,
                            0,
                        ))
                    }
                    .await;
                    let _ = channel.send(ret);
                }
                WsEvent::Close(packet, channel) => {
                    if let Some((_, mut stream)) = self.stream_map.remove(&packet.stream_id) {
                        stream.stream.disconnect();
                        stream.stream.close_channel();
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::EndFut(x) => {
                    if let Some(reason) = x {
                        let _ = self
                            .tx
                            .write_frame(Packet::new_close(0, reason).into())
                            .await;
                    }
                    break;
                }
            }
        }
    }

    async fn server_loop<R>(
        &self,
        mut rx: R,
        mut extensions: Vec<AnyProtocolExtension>,
        muxstream_sender: mpsc::UnboundedSender<(ConnectPacket, MuxStream)>,
        close_tx: mpsc::Sender<WsEvent>,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead + Send,
    {
        // will send continues once flow_control is at 10% of max
        let target_buffer_size = ((self.buffer_size as u64 * 90) / 100) as u32;

        loop {
            let frame = rx.wisp_read_frame(&self.tx).await?;
            if frame.opcode == ws::OpCode::Close {
                break Ok(());
            }
            if let Some(packet) =
                Packet::maybe_handle_extension(frame, &mut extensions, &mut rx, &self.tx).await?
            {
                use PacketType::*;
                match packet.packet_type {
                    Connect(inner_packet) => {
                        let (ch_tx, ch_rx) = mpsc::unbounded();
                        let stream_type = inner_packet.stream_type;
                        let flow_control: Arc<AtomicU32> = AtomicU32::new(self.buffer_size).into();
                        let flow_control_event: Arc<Event> = Event::new().into();
                        let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();

                        self.stream_map.insert(
                            packet.stream_id,
                            MuxMapValue {
                                stream: ch_tx,
                                stream_type,
                                flow_control: flow_control.clone(),
                                flow_control_event: flow_control_event.clone(),
                                is_closed: is_closed.clone(),
                            },
                        );
                        muxstream_sender
                            .unbounded_send((
                                inner_packet,
                                MuxStream::new(
                                    packet.stream_id,
                                    Role::Server,
                                    stream_type,
                                    ch_rx,
                                    close_tx.clone(),
                                    is_closed,
                                    flow_control,
                                    flow_control_event,
                                    target_buffer_size,
                                ),
                            ))
                            .map_err(|x| WispError::Other(Box::new(x)))?;
                    }
                    Data(data) => {
                        if let Some(stream) = self.stream_map.get(&packet.stream_id) {
                            let _ = stream.stream.unbounded_send(data);
                            if stream.stream_type == StreamType::Tcp {
                                stream.flow_control.store(
                                    stream
                                        .flow_control
                                        .load(Ordering::Acquire)
                                        .saturating_sub(1),
                                    Ordering::Release,
                                );
                            }
                        }
                    }
                    Continue(_) | Info(_) => break Err(WispError::InvalidPacketType),
                    Close(_) => {
                        if packet.stream_id == 0 {
                            break Ok(());
                        }
                        if let Some((_, mut stream)) = self.stream_map.remove(&packet.stream_id) {
                            stream.is_closed.store(true, Ordering::Release);
                            stream.stream.disconnect();
                            stream.stream.close_channel();
                        }
                    }
                }
            }
        }
    }

    async fn client_loop<R>(
        &self,
        mut rx: R,
        mut extensions: Vec<AnyProtocolExtension>,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead + Send,
    {
        loop {
            let frame = rx.wisp_read_frame(&self.tx).await?;
            if frame.opcode == ws::OpCode::Close {
                break Ok(());
            }
            if let Some(packet) =
                Packet::maybe_handle_extension(frame, &mut extensions, &mut rx, &self.tx).await?
            {
                use PacketType::*;
                match packet.packet_type {
                    Connect(_) | Info(_) => break Err(WispError::InvalidPacketType),
                    Data(data) => {
                        if let Some(stream) = self.stream_map.get(&packet.stream_id) {
                            let _ = stream.stream.unbounded_send(data);
                        }
                    }
                    Continue(inner_packet) => {
                        if let Some(stream) = self.stream_map.get(&packet.stream_id) {
                            if stream.stream_type == StreamType::Tcp {
                                stream
                                    .flow_control
                                    .store(inner_packet.buffer_remaining, Ordering::Release);
                                let _ = stream.flow_control_event.notify(u32::MAX);
                            }
                        }
                    }
                    Close(_) => {
                        if packet.stream_id == 0 {
                            break Ok(());
                        }
                        if let Some((_, mut stream)) = self.stream_map.remove(&packet.stream_id) {
                            stream.is_closed.store(true, Ordering::Release);
                            stream.stream.disconnect();
                            stream.stream.close_channel();
                        }
                    }
                }
            }
        }
    }
}

/// Server-side multiplexor.
///
/// # Example
/// ```
/// use wisp_mux::ServerMux;
///
/// let (mux, fut) = ServerMux::new(rx, tx, 128, Some(vec![]), Some([]));
/// tokio::spawn(async move {
///     if let Err(e) = fut.await {
///         println!("error in multiplexor: {:?}", e);
///     }
/// });
/// while let Some((packet, stream)) = mux.server_new_stream().await {
///     tokio::spawn(async move {
///         let url = format!("{}:{}", packet.destination_hostname, packet.destination_port);
///         // do something with `url` and `packet.stream_type`
///     });
/// }
/// ```
pub struct ServerMux {
    /// Whether the connection was downgraded to Wisp v1.
    ///
    /// If this variable is true you must assume no extensions are supported.
    pub downgraded: bool,
    /// Extensions that are supported by both sides.
    pub supported_extension_ids: Vec<u8>,
    close_tx: mpsc::Sender<WsEvent>,
    muxstream_recv: mpsc::UnboundedReceiver<(ConnectPacket, MuxStream)>,
}

impl ServerMux {
    /// Create a new server-side multiplexor.
    ///
    /// If extension_builders is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
    pub async fn new<R, W>(
        mut read: R,
        write: W,
        buffer_size: u32,
        extension_builders: Option<&[&(dyn ProtocolExtensionBuilder + Sync)]>,
    ) -> Result<(Self, impl Future<Output = Result<(), WispError>> + Send), WispError>
    where
        R: ws::WebSocketRead + Send,
        W: ws::WebSocketWrite + Send + 'static,
    {
        let (close_tx, close_rx) = mpsc::channel::<WsEvent>(256);
        let (tx, rx) = mpsc::unbounded::<(ConnectPacket, MuxStream)>();
        let write = ws::LockedWebSocketWrite::new(Box::new(write));

        write
            .write_frame(Packet::new_continue(0, buffer_size).into())
            .await?;

        let mut supported_extensions = Vec::new();
        let mut extra_packet = Vec::with_capacity(1);
        let mut downgraded = true;

        if let Some(builders) = extension_builders {
            let extensions: Vec<_> = builders
                .iter()
                .map(|x| x.build_to_extension(Role::Server))
                .collect();
            let extension_ids: Vec<_> = extensions.iter().map(|x| x.get_id()).collect();
            write
                .write_frame(Packet::new_info(extensions).into())
                .await?;
            if let Some(frame) = select! {
                x = read.wisp_read_frame(&write).fuse() => Some(x?),
                _ = Delay::new(Duration::from_secs(5)).fuse() => None
            } {
                let packet = Packet::maybe_parse_info(frame, Role::Server, builders)?;
                if let PacketType::Info(info) = packet.packet_type {
                    supported_extensions = info
                        .extensions
                        .into_iter()
                        .filter(|x| extension_ids.contains(&x.get_id()))
                        .collect();
                    downgraded = false;
                } else {
                    extra_packet.push(packet.into());
                }
            }
        }

        Ok((
            Self {
                muxstream_recv: rx,
                close_tx: close_tx.clone(),
                downgraded,
                supported_extension_ids: supported_extensions.iter().map(|x| x.get_id()).collect(),
            },
            MuxInner {
                tx: write,
                stream_map: DashMap::new(),
                buffer_size,
            }
            .server_into_future(
                AppendingWebSocketRead(extra_packet, read),
                supported_extensions,
                close_rx,
                tx,
                close_tx,
            ),
        ))
    }

    /// Wait for a stream to be created.
    pub async fn server_new_stream(&mut self) -> Option<(ConnectPacket, MuxStream)> {
        self.muxstream_recv.next().await
    }

    async fn close_internal(&mut self, reason: Option<CloseReason>) -> Result<(), WispError> {
        self.close_tx
            .send(WsEvent::EndFut(reason))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)
    }

    /// Close all streams.
    ///
    /// Also terminates the multiplexor future. Waiting for a new stream will never succeed after
    /// this function is called.
    pub async fn close(&mut self) -> Result<(), WispError> {
        self.close_internal(None).await
    }

    /// Close all streams and send an extension incompatibility error to the client.
    ///
    /// Also terminates the multiplexor future. Waiting for a new stream will never succed after
    /// this function is called.
    pub async fn close_extension_incompat(&mut self) -> Result<(), WispError> {
        self.close_internal(Some(CloseReason::IncompatibleExtensions))
            .await
    }
}
/// Client side multiplexor.
///
/// # Example
/// ```
/// use wisp_mux::{ClientMux, StreamType};
///
/// let (mux, fut) = ClientMux::new(rx, tx, Some(vec![]), []).await?;
/// tokio::spawn(async move {
///     if let Err(e) = fut.await {
///         println!("error in multiplexor: {:?}", e);
///     }
/// });
/// let stream = mux.client_new_stream(StreamType::Tcp, "google.com", 80);
/// ```
pub struct ClientMux {
    /// Whether the connection was downgraded to Wisp v1.
    ///
    /// If this variable is true you must assume no extensions are supported.
    pub downgraded: bool,
    /// Extensions that are supported by both sides.
    pub supported_extension_ids: Vec<u8>,
    close_tx: mpsc::Sender<WsEvent>,
}

impl ClientMux {
    /// Create a new client side multiplexor.
    ///
    /// If extension_builders is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
    pub async fn new<R, W>(
        mut read: R,
        write: W,
        extension_builders: Option<&[&(dyn ProtocolExtensionBuilder + Sync)]>,
    ) -> Result<(Self, impl Future<Output = Result<(), WispError>> + Send), WispError>
    where
        R: ws::WebSocketRead + Send,
        W: ws::WebSocketWrite + Send + 'static,
    {
        let write = ws::LockedWebSocketWrite::new(Box::new(write));
        let first_packet = Packet::try_from(read.wisp_read_frame(&write).await?)?;
        if first_packet.stream_id != 0 {
            return Err(WispError::InvalidStreamId);
        }
        if let PacketType::Continue(packet) = first_packet.packet_type {
            let mut supported_extensions = Vec::new();
            let mut extra_packet = Vec::with_capacity(1);
            let mut downgraded = true;

            if let Some(builders) = extension_builders {
                let extensions: Vec<_> = builders
                    .iter()
                    .map(|x| x.build_to_extension(Role::Client))
                    .collect();
                let extension_ids: Vec<_> = extensions.iter().map(|x| x.get_id()).collect();
                if let Some(frame) = select! {
                    x = read.wisp_read_frame(&write).fuse() => Some(x?),
                    _ = Delay::new(Duration::from_secs(5)).fuse() => None
                } {
                    let packet = Packet::maybe_parse_info(frame, Role::Client, builders)?;
                    if let PacketType::Info(info) = packet.packet_type {
                        supported_extensions = info
                            .extensions
                            .into_iter()
                            .filter(|x| extension_ids.contains(&x.get_id()))
                            .collect();
                        write
                            .write_frame(Packet::new_info(extensions).into())
                            .await?;
                        downgraded = false;
                    } else {
                        extra_packet.push(packet.into());
                    }
                }
            }

            for extension in supported_extensions.iter_mut() {
                extension.handle_handshake(&mut read, &write).await?;
            }

            let (tx, rx) = mpsc::channel::<WsEvent>(256);
            Ok((
                Self {
                    close_tx: tx.clone(),
                    downgraded,
                    supported_extension_ids: supported_extensions
                        .iter()
                        .map(|x| x.get_id())
                        .collect(),
                },
                MuxInner {
                    tx: write,
                    stream_map: DashMap::new(),
                    buffer_size: packet.buffer_remaining,
                }
                .client_into_future(
                    AppendingWebSocketRead(extra_packet, read),
                    supported_extensions,
                    rx,
                    tx,
                ),
            ))
        } else {
            Err(WispError::InvalidPacketType)
        }
    }

    /// Create a new stream, multiplexed through Wisp.
    pub async fn client_new_stream(
        &mut self,
        stream_type: StreamType,
        host: String,
        port: u16,
    ) -> Result<MuxStream, WispError> {
        if stream_type == StreamType::Udp
            && !self
                .supported_extension_ids
                .iter()
                .any(|x| *x == UdpProtocolExtension::ID)
        {
            return Err(WispError::UdpExtensionNotSupported);
        }
        let (tx, rx) = oneshot::channel();
        self.close_tx
            .send(WsEvent::CreateStream(stream_type, host, port, tx))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)?;
        rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)?
    }

    async fn close_internal(&mut self, reason: Option<CloseReason>) -> Result<(), WispError> {
        self.close_tx
            .send(WsEvent::EndFut(reason))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)
    }

    /// Close all streams.
    ///
    /// Also terminates the multiplexor future. Creating a stream is UB after calling this
    /// function.
    pub async fn close(&mut self) -> Result<(), WispError> {
        self.close_internal(None).await
    }

    /// Close all streams and send an extension incompatibility error to the client.
    ///
    /// Also terminates the multiplexor future. Creating a stream is UB after calling this
    /// function.
    pub async fn close_extension_incompat(&mut self) -> Result<(), WispError> {
        self.close_internal(Some(CloseReason::IncompatibleExtensions))
            .await
    }
}
