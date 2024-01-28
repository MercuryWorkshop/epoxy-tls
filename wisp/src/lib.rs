#[cfg(feature = "fastwebsockets")]
mod fastwebsockets;
mod packet;
pub mod ws;
#[cfg(feature = "ws_stream_wasm")]
mod ws_stream_wasm;

pub use crate::packet::*;

use bytes::Bytes;
use dashmap::DashMap;
use futures::{channel::mpsc, channel::oneshot, SinkExt, StreamExt};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};

#[derive(Debug, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug)]
pub enum WispError {
    PacketTooSmall,
    InvalidPacketType,
    InvalidStreamType,
    InvalidStreamId,
    MaxStreamCountReached,
    StreamAlreadyClosed,
    WsFrameInvalidType,
    WsFrameNotFinished,
    WsImplError(Box<dyn std::error::Error + Sync + Send>),
    WsImplSocketClosed,
    WsImplNotSupported,
    Utf8Error(std::str::Utf8Error),
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
            MaxStreamCountReached => write!(f, "Maximum stream count reached"),
            StreamAlreadyClosed => write!(f, "Stream already closed"),
            WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
            WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
            WsImplError(err) => write!(f, "Websocket implementation error: {:?}", err),
            WsImplSocketClosed => write!(f, "Websocket implementation error: websocket closed"),
            WsImplNotSupported => write!(f, "Websocket implementation error: unsupported feature"),
            Utf8Error(err) => write!(f, "UTF-8 error: {:?}", err),
            Other(err) => write!(f, "Other error: {:?}", err),
        }
    }
}

impl std::error::Error for WispError {}

pub enum WsEvent {
    Send(Bytes),
    Close(ClosePacket),
}

pub enum MuxEvent {
    Close(u32, u8, oneshot::Sender<Result<(), WispError>>),
}

pub struct MuxStream<W>
where
    W: ws::WebSocketWrite,
{
    pub stream_id: u32,
    rx: mpsc::UnboundedReceiver<WsEvent>,
    tx: ws::LockedWebSocketWrite<W>,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
}

impl<W: ws::WebSocketWrite> MuxStream<W> {
    pub async fn read(&mut self) -> Option<WsEvent> {
        if self.is_closed.load(Ordering::Acquire) {
            return None;
        }
        match self.rx.next().await? {
            WsEvent::Send(bytes) => Some(WsEvent::Send(bytes)),
            WsEvent::Close(packet) => {
                self.is_closed.store(true, Ordering::Release);
                Some(WsEvent::Close(packet))
            }
        }
    }

    pub async fn write(&mut self, data: Bytes) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        self.tx
            .write_frame(Packet::new_data(self.stream_id, data).into())
            .await
    }

    pub fn get_close_handle(&self) -> MuxStreamCloser {
        MuxStreamCloser {
            stream_id: self.stream_id,
            close_channel: self.close_channel.clone(),
            is_closed: self.is_closed.clone(),
        }
    }

    pub async fn close(&mut self, reason: u8) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
        self.close_channel
            .send(MuxEvent::Close(self.stream_id, reason, tx))
            .await
            .map_err(|x| WispError::Other(Box::new(x)))?;
        rx.await.map_err(|x| WispError::Other(Box::new(x)))??;
        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }
}

pub struct MuxStreamCloser {
    stream_id: u32,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamCloser {
    pub async fn close(&mut self, reason: u8) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
        self.close_channel
            .send(MuxEvent::Close(self.stream_id, reason, tx))
            .await
            .map_err(|x| WispError::Other(Box::new(x)))?;
        rx.await.map_err(|x| WispError::Other(Box::new(x)))??;
        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }
}

pub struct ServerMux<R, W>
where
    R: ws::WebSocketRead,
    W: ws::WebSocketWrite,
{
    rx: R,
    tx: ws::LockedWebSocketWrite<W>,
    stream_map: Arc<DashMap<u32, mpsc::UnboundedSender<WsEvent>>>,
    close_rx: mpsc::UnboundedReceiver<MuxEvent>,
    close_tx: mpsc::UnboundedSender<MuxEvent>,
}

impl<R: ws::WebSocketRead, W: ws::WebSocketWrite> ServerMux<R, W> {
    pub fn new(read: R, write: W) -> Self {
        let (tx, rx) = mpsc::unbounded::<MuxEvent>();
        Self {
            rx: read,
            tx: ws::LockedWebSocketWrite::new(write),
            stream_map: Arc::new(DashMap::new()),
            close_rx: rx,
            close_tx: tx,
        }
    }

    pub async fn server_bg_loop(&mut self) {
        while let Some(msg) = self.close_rx.next().await {
            match msg {
                MuxEvent::Close(stream_id, reason, channel) => {
                    if self.stream_map.clone().remove(&stream_id).is_some() {
                        let _ = channel.send(
                            self.tx
                                .write_frame(Packet::new_close(stream_id, reason).into())
                                .await,
                        );
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
            }
        }
    }

    pub async fn server_loop<FR>(
        &mut self,
        handler_fn: &mut impl Fn(ConnectPacket, MuxStream<W>) -> FR,
    ) -> Result<(), WispError>
    where
        FR: std::future::Future<Output = Result<(), crate::WispError>>,
    {
        self.tx
            .write_frame(Packet::new_continue(0, u32::MAX).into())
            .await?;

        while let Ok(frame) = self.rx.wisp_read_frame(&mut self.tx).await {
            if let Ok(packet) = Packet::try_from(frame) {
                use PacketType::*;
                match packet.packet {
                    Connect(inner_packet) => {
                        let (ch_tx, ch_rx) = mpsc::unbounded();
                        self.stream_map.clone().insert(packet.stream_id, ch_tx);
                        let _ = handler_fn(
                            inner_packet,
                            MuxStream {
                                stream_id: packet.stream_id,
                                rx: ch_rx,
                                tx: self.tx.clone(),
                                close_channel: self.close_tx.clone(),
                                is_closed: AtomicBool::new(false).into(),
                            },
                        )
                        .await;
                    }
                    Data(data) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Send(data));
                            self.tx
                                .write_frame(
                                    Packet::new_continue(packet.stream_id, u32::MAX).into(),
                                )
                                .await?;
                        }
                    }
                    Continue(_) => unreachable!(),
                    Close(inner_packet) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Close(inner_packet));
                            self.stream_map.clone().remove(&packet.stream_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct ClientMux<R, W>
where
    R: ws::WebSocketRead,
    W: ws::WebSocketWrite,
{
    rx: R,
    tx: ws::LockedWebSocketWrite<W>,
    stream_map: Arc<DashMap<u32, mpsc::UnboundedSender<WsEvent>>>,
    next_free_stream_id: AtomicU32,
    close_rx: mpsc::UnboundedReceiver<MuxEvent>,
    close_tx: mpsc::UnboundedSender<MuxEvent>,
}

impl<R: ws::WebSocketRead, W: ws::WebSocketWrite> ClientMux<R, W> {
    pub fn new(read: R, write: W) -> Self {
        let (tx, rx) = mpsc::unbounded::<MuxEvent>();
        Self {
            rx: read,
            tx: ws::LockedWebSocketWrite::new(write),
            stream_map: Arc::new(DashMap::new()),
            next_free_stream_id: AtomicU32::new(1),
            close_rx: rx,
            close_tx: tx,
        }
    }

    pub async fn client_bg_loop(&mut self) {
        while let Some(msg) = self.close_rx.next().await {
            match msg {
                MuxEvent::Close(stream_id, reason, channel) => {
                    if self.stream_map.clone().remove(&stream_id).is_some() {
                        let _ = channel.send(
                            self.tx
                                .write_frame(Packet::new_close(stream_id, reason).into())
                                .await,
                        );
                    } else {
                        let _ = channel.send(Err(WispError::InvalidStreamId));
                    }
                }
            }
        }
    }

    pub async fn client_loop(&mut self) -> Result<(), WispError> {
        self.tx
            .write_frame(Packet::new_continue(0, u32::MAX).into())
            .await?;

        while let Ok(frame) = self.rx.wisp_read_frame(&mut self.tx).await {
            if let Ok(packet) = Packet::try_from(frame) {
                use PacketType::*;
                match packet.packet {
                    Connect(_) => unreachable!(),
                    Data(data) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Send(data));
                        }
                    }
                    Continue(_) => {}
                    Close(inner_packet) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Close(inner_packet));
                            self.stream_map.clone().remove(&packet.stream_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn client_new_stream(
        &mut self,
    ) -> Result<MuxStream<impl ws::WebSocketWrite>, WispError> {
        let (ch_tx, ch_rx) = mpsc::unbounded();
        let stream_id = self.next_free_stream_id.load(Ordering::Acquire);
        self.next_free_stream_id.store(
            stream_id
                .checked_add(1)
                .ok_or(WispError::MaxStreamCountReached)?,
            Ordering::Release,
        );
        self.stream_map.clone().insert(stream_id, ch_tx);
        Ok(MuxStream {
            stream_id,
            rx: ch_rx,
            tx: self.tx.clone(),
            close_channel: self.close_tx.clone(),
            is_closed: AtomicBool::new(false).into(),
        })
    }
}
