//! Abstraction over WebSocket implementations.
//!
//! Use the [`fastwebsockets`] implementation of these traits as an example for implementing them
//! for other WebSocket implementations.
//!
//! [`fastwebsockets`]: https://github.com/MercuryWorkshop/epoxy-tls/blob/multiplexed/wisp/src/fastwebsockets.rs
use bytes::Bytes;
use futures::lock::Mutex;
use std::sync::Arc;

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
pub trait WebSocketRead {
    /// Read a frame from the socket.
    fn wisp_read_frame(
        &mut self,
        tx: &crate::ws::LockedWebSocketWrite<impl crate::ws::WebSocketWrite>,
    ) -> impl std::future::Future<Output = Result<Frame, crate::WispError>>;
}

/// Generic WebSocket write trait.
pub trait WebSocketWrite {
    /// Write a frame to the socket.
    fn wisp_write_frame(
        &mut self,
        frame: Frame,
    ) -> impl std::future::Future<Output = Result<(), crate::WispError>>;
}

/// Locked WebSocket that can be shared between threads.
pub struct LockedWebSocketWrite<S>(Arc<Mutex<S>>);

impl<S: WebSocketWrite> LockedWebSocketWrite<S> {
    /// Create a new locked websocket.
    pub fn new(ws: S) -> Self {
        Self(Arc::new(Mutex::new(ws)))
    }

    /// Write a frame to the websocket.
    pub async fn write_frame(&self, frame: Frame) -> Result<(), crate::WispError> {
        self.0.lock().await.wisp_write_frame(frame).await
    }
}

impl<S: WebSocketWrite> Clone for LockedWebSocketWrite<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
