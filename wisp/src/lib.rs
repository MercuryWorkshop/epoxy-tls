#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A library for easily creating [Wisp] clients and servers.
//!
//! [Wisp]: https://github.com/MercuryWorkshop/wisp-protocol

#[cfg(feature = "fastwebsockets")]
#[cfg_attr(docsrs, doc(cfg(feature = "fastwebsockets")))]
mod fastwebsockets;
mod packet;
mod sink_unfold;
mod stream;
pub mod ws;

pub use crate::packet::*;
pub use crate::stream::*;

use bytes::Bytes;
use event_listener::Event;
use futures::{channel::mpsc, lock::Mutex, Future, FutureExt, StreamExt};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};

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
    /// The packet recieved did not have enough data.
    PacketTooSmall,
    /// The packet recieved had an invalid type.
    InvalidPacketType,
    /// The stream had an invalid type.
    InvalidStreamType,
    /// The stream had an invalid ID.
    InvalidStreamId,
    /// The close packet had an invalid reason.
    InvalidCloseReason,
    /// The URI recieved was invalid.
    InvalidUri,
    /// The URI recieved had no host.
    UriHasNoHost,
    /// The URI recieved had no port.
    UriHasNoPort,
    /// The max stream count was reached.
    MaxStreamCountReached,
    /// The stream had already been closed.
    StreamAlreadyClosed,
    /// The websocket frame recieved had an invalid type.
    WsFrameInvalidType,
    /// The websocket frame recieved was not finished.
    WsFrameNotFinished,
    /// Error specific to the websocket implementation.
    WsImplError(Box<dyn std::error::Error + Sync + Send>),
    /// The websocket implementation socket closed.
    WsImplSocketClosed,
    /// The websocket implementation did not support the action.
    WsImplNotSupported,
    /// The string was invalid UTF-8.
    Utf8Error(std::str::Utf8Error),
    /// Other error.
    Other(Box<dyn std::error::Error + Sync + Send>),
}

impl From<std::str::Utf8Error> for WispError {
    fn from(err: std::str::Utf8Error) -> WispError {
        WispError::Utf8Error(err)
    }
}

impl std::fmt::Display for WispError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use WispError::*;
        match self {
            PacketTooSmall => write!(f, "Packet too small"),
            InvalidPacketType => write!(f, "Invalid packet type"),
            InvalidStreamType => write!(f, "Invalid stream type"),
            InvalidStreamId => write!(f, "Invalid stream id"),
            InvalidCloseReason => write!(f, "Invalid close reason"),
            InvalidUri => write!(f, "Invalid URI"),
            UriHasNoHost => write!(f, "URI has no host"),
            UriHasNoPort => write!(f, "URI has no port"),
            MaxStreamCountReached => write!(f, "Maximum stream count reached"),
            StreamAlreadyClosed => write!(f, "Stream already closed"),
            WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
            WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
            WsImplError(err) => write!(f, "Websocket implementation error: {}", err),
            WsImplSocketClosed => write!(f, "Websocket implementation error: websocket closed"),
            WsImplNotSupported => write!(f, "Websocket implementation error: unsupported feature"),
            Utf8Error(err) => write!(f, "UTF-8 error: {}", err),
            Other(err) => write!(f, "Other error: {}", err),
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

struct ServerMuxInner<W>
where
    W: ws::WebSocketWrite,
{
    tx: ws::LockedWebSocketWrite<W>,
    stream_map: Arc<Mutex<HashMap<u32, MuxMapValue>>>,
    close_tx: mpsc::UnboundedSender<WsEvent>,
}

impl<W: ws::WebSocketWrite> ServerMuxInner<W> {
    pub async fn into_future<R>(
        self,
        rx: R,
        close_rx: mpsc::UnboundedReceiver<WsEvent>,
        muxstream_sender: mpsc::UnboundedSender<(ConnectPacket, MuxStream)>,
        buffer_size: u32,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead,
    {
        let ret = futures::select! {
            x = self.server_bg_loop(close_rx).fuse() => x,
            x = self.server_msg_loop(rx, muxstream_sender, buffer_size).fuse() => x
        };
        self.stream_map.lock().await.drain().for_each(|mut x| {
            x.1.is_closed.store(true, Ordering::Release);
            x.1.stream.disconnect();
            x.1.stream.close_channel();
        });
        ret
    }

    async fn server_bg_loop(
        &self,
        mut close_rx: mpsc::UnboundedReceiver<WsEvent>,
    ) -> Result<(), WispError> {
        while let Some(msg) = close_rx.next().await {
            match msg {
                WsEvent::SendPacket(packet, channel) => {
                    if self
                        .stream_map
                        .lock()
                        .await
                        .get(&packet.stream_id)
                        .is_some()
                    {
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::Close(packet, channel) => {
                    if let Some(mut stream) =
                        self.stream_map.lock().await.remove(&packet.stream_id)
                    {
                        stream.stream.disconnect();
                        stream.stream.close_channel();
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::EndFut => break,
            }
        }
        Ok(())
    }

    async fn server_msg_loop<R>(
        &self,
        mut rx: R,
        muxstream_sender: mpsc::UnboundedSender<(ConnectPacket, MuxStream)>,
        buffer_size: u32,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead,
    {
        // will send continues once flow_control is at 10% of max
        let target_buffer_size = buffer_size * 90 / 100;
        self.tx
            .write_frame(Packet::new_continue(0, buffer_size).into())
            .await?;

        loop {
            let frame = rx.wisp_read_frame(&self.tx).await?;
            if frame.opcode == ws::OpCode::Close {
                break Ok(());
            }
            let packet = Packet::try_from(frame)?;

            use PacketType::*;
            match packet.packet_type {
                Connect(inner_packet) => {
                    let (ch_tx, ch_rx) = mpsc::unbounded();
                    let stream_type = inner_packet.stream_type;
                    let flow_control: Arc<AtomicU32> = AtomicU32::new(buffer_size).into();
                    let flow_control_event: Arc<Event> = Event::new().into();
                    let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();

                    self.stream_map.lock().await.insert(
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
                                self.close_tx.clone(),
                                is_closed,
                                flow_control,
                                flow_control_event,
                                target_buffer_size,
                            ),
                        ))
                        .map_err(|x| WispError::Other(Box::new(x)))?;
                }
                Data(data) => {
                    if let Some(stream) = self.stream_map.lock().await.get(&packet.stream_id) {
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
                Continue(_) => break Err(WispError::InvalidPacketType),
                Close(_) => {
                    if let Some(mut stream) =
                        self.stream_map.lock().await.remove(&packet.stream_id)
                    {
                        stream.is_closed.store(true, Ordering::Release);
                        stream.stream.disconnect();
                        stream.stream.close_channel();
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
/// let (mux, fut) = ServerMux::new(rx, tx, 128);
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
    stream_map: Arc<Mutex<HashMap<u32, MuxMapValue>>>,
    close_tx: mpsc::UnboundedSender<WsEvent>,
    muxstream_recv: mpsc::UnboundedReceiver<(ConnectPacket, MuxStream)>,
}

impl ServerMux {
    /// Create a new server-side multiplexor.
    pub fn new<R, W: ws::WebSocketWrite>(
        read: R,
        write: W,
        buffer_size: u32,
    ) -> (Self, impl Future<Output = Result<(), WispError>>)
    where
        R: ws::WebSocketRead,
    {
        let (close_tx, close_rx) = mpsc::unbounded::<WsEvent>();
        let (tx, rx) = mpsc::unbounded::<(ConnectPacket, MuxStream)>();
        let write = ws::LockedWebSocketWrite::new(write);
        let map = Arc::new(Mutex::new(HashMap::new()));
        (
            Self {
                muxstream_recv: rx,
                close_tx: close_tx.clone(),
                stream_map: map.clone(),
            },
            ServerMuxInner {
                tx: write,
                close_tx,
                stream_map: map.clone(),
            }
            .into_future(read, close_rx, tx, buffer_size),
        )
    }

    /// Wait for a stream to be created.
    pub async fn server_new_stream(&mut self) -> Option<(ConnectPacket, MuxStream)> {
        self.muxstream_recv.next().await
    }

    /// Close all streams.
    ///
    /// Also terminates the multiplexor future. Waiting for a new stream will never succeed after
    /// this function is called.
    pub async fn close(&self) {
        self.stream_map.lock().await.drain().for_each(|mut x| {
            x.1.is_closed.store(true, Ordering::Release);
            x.1.stream.disconnect();
            x.1.stream.close_channel();
        });
        let _ = self.close_tx.unbounded_send(WsEvent::EndFut);
    }
}

struct ClientMuxInner<W>
where
    W: ws::WebSocketWrite,
{
    tx: ws::LockedWebSocketWrite<W>,
    stream_map: Arc<Mutex<HashMap<u32, MuxMapValue>>>,
}

impl<W: ws::WebSocketWrite> ClientMuxInner<W> {
    pub(crate) async fn into_future<R>(
        self,
        rx: R,
        close_rx: mpsc::UnboundedReceiver<WsEvent>,
    ) -> Result<(), WispError>
    where
        R: ws::WebSocketRead,
    {
        let ret = futures::select! {
            x = self.client_bg_loop(close_rx).fuse() => x,
            x = self.client_loop(rx).fuse() => x
        };
        self.stream_map.lock().await.drain().for_each(|mut x| {
            x.1.is_closed.store(true, Ordering::Release);
            x.1.stream.disconnect();
            x.1.stream.close_channel();
        });
        ret
    }

    async fn client_bg_loop(
        &self,
        mut close_rx: mpsc::UnboundedReceiver<WsEvent>,
    ) -> Result<(), WispError> {
        while let Some(msg) = close_rx.next().await {
            match msg {
                WsEvent::SendPacket(packet, channel) => {
                    if self
                        .stream_map
                        .lock()
                        .await
                        .get(&packet.stream_id)
                        .is_some()
                    {
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::Close(packet, channel) => {
                    if let Some(mut stream) =
                        self.stream_map.lock().await.remove(&packet.stream_id)
                    {
                        stream.stream.disconnect();
                        stream.stream.close_channel();
                        let _ = channel.send(self.tx.write_frame(packet.into()).await);
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
                WsEvent::EndFut => break,
            }
        }
        Ok(())
    }

    async fn client_loop<R>(&self, mut rx: R) -> Result<(), WispError>
    where
        R: ws::WebSocketRead,
    {
        loop {
            let frame = rx.wisp_read_frame(&self.tx).await?;
            if frame.opcode == ws::OpCode::Close {
                break Ok(());
            }
            let packet = Packet::try_from(frame)?;

            use PacketType::*;
            match packet.packet_type {
                Connect(_) => break Err(WispError::InvalidPacketType),
                Data(data) => {
                    if let Some(stream) = self.stream_map.lock().await.get(&packet.stream_id) {
                        let _ = stream.stream.unbounded_send(data);
                    }
                }
                Continue(inner_packet) => {
                    if let Some(stream) = self.stream_map.lock().await.get(&packet.stream_id) {
                        if stream.stream_type == StreamType::Tcp {
                            stream
                                .flow_control
                                .store(inner_packet.buffer_remaining, Ordering::Release);
                            let _ = stream.flow_control_event.notify(u32::MAX);
                        }
                    }
                }
                Close(_) => {
                    if let Some(mut stream) =
                        self.stream_map.lock().await.remove(&packet.stream_id)
                    {
                        stream.is_closed.store(true, Ordering::Release);
                        stream.stream.disconnect();
                        stream.stream.close_channel();
                    }
                }
            }
        }
    }
}

/// Client side multiplexor.
///
/// # Example
/// ```
/// use wisp_mux::{ClientMux, StreamType};
///
/// let (mux, fut) = ClientMux::new(rx, tx).await?;
/// tokio::spawn(async move {
///     if let Err(e) = fut.await {
///         println!("error in multiplexor: {:?}", e);
///     }
/// });
/// let stream = mux.client_new_stream(StreamType::Tcp, "google.com", 80);
/// ```
pub struct ClientMux<W>
where
    W: ws::WebSocketWrite,
{
    tx: ws::LockedWebSocketWrite<W>,
    stream_map: Arc<Mutex<HashMap<u32, MuxMapValue>>>,
    next_free_stream_id: AtomicU32,
    close_tx: mpsc::UnboundedSender<WsEvent>,
    buf_size: u32,
    target_buf_size: u32,
}

impl<W: ws::WebSocketWrite> ClientMux<W> {
    /// Create a new client side multiplexor.
    pub async fn new<R>(
        mut read: R,
        write: W,
    ) -> Result<(Self, impl Future<Output = Result<(), WispError>>), WispError>
    where
        R: ws::WebSocketRead,
    {
        let write = ws::LockedWebSocketWrite::new(write);
        let first_packet = Packet::try_from(read.wisp_read_frame(&write).await?)?;
        if first_packet.stream_id != 0 {
            return Err(WispError::InvalidStreamId);
        }
        if let PacketType::Continue(packet) = first_packet.packet_type {
            let (tx, rx) = mpsc::unbounded::<WsEvent>();
            let map = Arc::new(Mutex::new(HashMap::new()));
            Ok((
                Self {
                    tx: write.clone(),
                    stream_map: map.clone(),
                    next_free_stream_id: AtomicU32::new(1),
                    close_tx: tx,
                    buf_size: packet.buffer_remaining,
                    // server-only
                    target_buf_size: 0,
                },
                ClientMuxInner {
                    tx: write.clone(),
                    stream_map: map.clone(),
                }
                .into_future(read, rx),
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
        let (ch_tx, ch_rx) = mpsc::unbounded();
        let stream_id = self.next_free_stream_id.load(Ordering::Acquire);
        let next_stream_id = stream_id
            .checked_add(1)
            .ok_or(WispError::MaxStreamCountReached)?;

        let flow_control_event: Arc<Event> = Event::new().into();
        let flow_control: Arc<AtomicU32> = AtomicU32::new(self.buf_size).into();

        let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();

        self.tx
            .write_frame(Packet::new_connect(stream_id, stream_type, port, host).into())
            .await?;

        self.next_free_stream_id
            .store(next_stream_id, Ordering::Release);

        self.stream_map.lock().await.insert(
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
            self.close_tx.clone(),
            is_closed,
            flow_control,
            flow_control_event,
            self.target_buf_size,
        ))
    }

    /// Close all streams.
    ///
    /// Also terminates the multiplexor future. Creating a stream is UB after calling this
    /// function.
    pub async fn close(&self) {
        self.stream_map.lock().await.drain().for_each(|mut x| {
            x.1.is_closed.store(true, Ordering::Release);
            x.1.stream.disconnect();
            x.1.stream.close_channel();
        });
        let _ = self.close_tx.unbounded_send(WsEvent::EndFut);
    }
}
