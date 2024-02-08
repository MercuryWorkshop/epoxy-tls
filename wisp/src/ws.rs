use bytes::Bytes;
use futures::lock::Mutex;
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

pub struct Frame {
    pub finished: bool,
    pub opcode: OpCode,
    pub payload: Bytes,
}

impl Frame {
    pub fn text(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Text,
            payload,
        }
    }

    pub fn binary(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Binary,
            payload,
        }
    }

    pub fn close(payload: Bytes) -> Self {
        Self {
            finished: true,
            opcode: OpCode::Close,
            payload,
        }
    }
}

pub trait WebSocketRead {
    fn wisp_read_frame(
        &mut self,
        tx: &crate::ws::LockedWebSocketWrite<impl crate::ws::WebSocketWrite + Send>,
    ) -> impl std::future::Future<Output = Result<Frame, crate::WispError>> + Send;
}

pub trait WebSocketWrite {
    fn wisp_write_frame(
        &mut self,
        frame: Frame,
    ) -> impl std::future::Future<Output = Result<(), crate::WispError>> + Send;
}

pub struct LockedWebSocketWrite<S>(Arc<Mutex<S>>);

impl<S: WebSocketWrite + Send> LockedWebSocketWrite<S> {
    pub fn new(ws: S) -> Self {
        Self(Arc::new(Mutex::new(ws)))
    }

    pub async fn write_frame(&self, frame: Frame) -> Result<(), crate::WispError> {
        self.0.lock().await.wisp_write_frame(frame).await
    }
}

impl<S: WebSocketWrite> Clone for LockedWebSocketWrite<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
