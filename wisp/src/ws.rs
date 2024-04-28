//! Abstraction over WebSocket implementations.
//!
//! Use the [`fastwebsockets`] implementation of these traits as an example for implementing them
//! for other WebSocket implementations.
//!
//! [`fastwebsockets`]: https://github.com/MercuryWorkshop/epoxy-tls/blob/multiplexed/wisp/src/fastwebsockets.rs
use std::sync::Arc;

use crate::WispError;
use async_trait::async_trait;
use bytes::BytesMut;
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
    pub payload: BytesMut,
}

impl Frame {
    /// Create a new text frame.
    pub fn text(payload: BytesMut) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Text,
            payload,
        }
    }

    /// Create a new binary frame.
    pub fn binary(payload: BytesMut) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Binary,
            payload,
        }
    }

    /// Create a new close frame.
    pub fn close(payload: BytesMut) -> Self {
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

    /// Close the socket.
    async fn wisp_close(&mut self) -> Result<(), WispError>;
}

/// Locked WebSocket.
#[derive(Clone)]
pub struct LockedWebSocketWrite(Arc<Mutex<Box<dyn WebSocketWrite + Send>>>);

impl LockedWebSocketWrite {
    /// Create a new locked websocket.
    pub fn new(ws: Box<dyn WebSocketWrite + Send>) -> Self {
        Self(Mutex::new(ws).into())
    }

    /// Write a frame to the websocket.
    pub async fn write_frame(&self, frame: Frame) -> Result<(), WispError> {
        self.0.lock().await.wisp_write_frame(frame).await
    }

    /// Close the websocket.
    pub async fn close(&self) -> Result<(), WispError> {
        self.0.lock().await.wisp_close().await
    }
}

pub(crate) struct AppendingWebSocketRead<R>(pub Option<Frame>, pub R)
where
    R: WebSocketRead + Send;

#[async_trait]
impl<R> WebSocketRead for AppendingWebSocketRead<R>
where
    R: WebSocketRead + Send,
{
    async fn wisp_read_frame(&mut self, tx: &LockedWebSocketWrite) -> Result<Frame, WispError> {
        if let Some(x) = self.0.take() {
            return Ok(x);
        }
        return self.1.wisp_read_frame(tx).await;
    }
}
