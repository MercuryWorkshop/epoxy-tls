//! Abstraction over WebSocket implementations.
//!
//! Use the [`fastwebsockets`] implementation of these traits as an example for implementing them
//! for other WebSocket implementations.
//!
//! [`fastwebsockets`]: https://github.com/MercuryWorkshop/epoxy-tls/blob/multiplexed/wisp/src/fastwebsockets.rs
use crate::WispError;
use async_trait::async_trait;
use bytes::Bytes;
use futures::lock::Mutex;

/// Opcode of the WebSocket frame.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
    /// Text frame.
    Text,
    /// Binary frame.
    Binary,
    /// Close frame.
    Close,
    /// Ping frame.
    Ping,
    /// Pong frame.
    Pong,
}

/// WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether the frame is finished or not.
    pub finished: bool,
    /// Opcode of the WebSocket frame.
    pub opcode: OpCode,
    /// Payload of the WebSocket frame.
    pub payload: Bytes,
}

impl Frame {
    /// Create a new text frame.
    pub fn text(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Text,
            payload,
        }
    }

    /// Create a new binary frame.
    pub fn binary(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Binary,
            payload,
        }
    }

    /// Create a new close frame.
    pub fn close(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Close,
            payload,
        }
    }
}

/// Generic WebSocket read trait.
#[async_trait]
pub trait WebSocketRead {
    /// Read a frame from the socket.
    async fn wisp_read_frame(&mut self, tx: &LockedWebSocketWrite) -> Result<Frame, WispError>;
}

/// Generic WebSocket write trait.
#[async_trait]
pub trait WebSocketWrite {
    /// Write a frame to the socket.
    async fn wisp_write_frame(&mut self, frame: Frame) -> Result<(), WispError>;
}

/// Locked WebSocket.
pub struct LockedWebSocketWrite(Mutex<Box<dyn WebSocketWrite + Send>>);

impl LockedWebSocketWrite {
    /// Create a new locked websocket.
    pub fn new(ws: Box<dyn WebSocketWrite + Send>) -> Self {
        Self(Mutex::new(ws))
    }

    /// Write a frame to the websocket.
    pub async fn write_frame(&self, frame: Frame) -> Result<(), crate::WispError> {
        self.0.lock().await.wisp_write_frame(frame).await
    }
}

pub(crate) struct AppendingWebSocketRead<R>(pub Vec<Frame>, pub R)
where
    R: WebSocketRead + Send;

#[async_trait]
impl<R> WebSocketRead for AppendingWebSocketRead<R>
where
    R: WebSocketRead + Send,
{
    async fn wisp_read_frame(&mut self, tx: &LockedWebSocketWrite) -> Result<Frame, WispError> {
        if let Some(x) = self.0.pop() {
            return Ok(x);
        }
        return self.1.wisp_read_frame(tx).await;
    }
}
