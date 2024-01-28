#[cfg(feature = "fastwebsockets")]
mod fastwebsockets;
mod packet;
pub mod ws;

pub use crate::packet::*;

use bytes::Bytes;
use dashmap::DashMap;
use futures::{channel::mpsc, StreamExt};
use std::sync::Arc;

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
    WsFrameInvalidType,
    WsFrameNotFinished,
    WsImplError(Box<dyn std::error::Error + Sync + Send>),
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
            WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
            WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
            WsImplError(err) => write!(f, "Websocket implementation error: {:?}", err),
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

pub struct MuxStream<W>
where
    W: ws::WebSocketWrite,
{
    pub stream_id: u32,
    rx: mpsc::UnboundedReceiver<WsEvent>,
    tx: ws::LockedWebSocketWrite<W>,
}

impl<W: ws::WebSocketWrite> MuxStream<W> {
    pub async fn read(&mut self) -> Option<WsEvent> {
        self.rx.next().await
    }

    pub async fn write(&mut self, data: Bytes) -> Result<(), WispError> {
        self.tx
            .write_frame(ws::Frame::from(Packet::new_data(self.stream_id, data)))
            .await
    }

    pub fn get_write_half(&self) -> ws::LockedWebSocketWrite<W> {
        self.tx.clone()
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
}

impl<R: ws::WebSocketRead, W: ws::WebSocketWrite> ServerMux<R, W> {
    pub fn new(read: R, write: W) -> Self {
        Self {
            rx: read,
            tx: ws::LockedWebSocketWrite::new(write),
            stream_map: Arc::new(DashMap::new()),
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
            .write_frame(ws::Frame::from(Packet::new_continue(0, u32::MAX)))
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
                            },
                        ).await;
                    }
                    Data(data) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Send(data));
                            self.tx
                                .write_frame(ws::Frame::from(Packet::new_continue(packet.stream_id, u32::MAX)))
                                .await?;
                        }
                    }
                    Continue(_) => unreachable!(),
                    Close(inner_packet) => {
                        if let Some(stream) = self.stream_map.clone().get(&packet.stream_id) {
                            let _ = stream.unbounded_send(WsEvent::Close(inner_packet));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
