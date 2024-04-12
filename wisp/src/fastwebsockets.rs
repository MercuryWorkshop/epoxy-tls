use async_trait::async_trait;
use bytes::Bytes;
use fastwebsockets::{
    FragmentCollectorRead, Frame, OpCode, Payload, WebSocketError, WebSocketWrite,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ws::LockedWebSocketWrite, WispError};

impl From<OpCode> for crate::ws::OpCode {
    fn from(opcode: OpCode) -> Self {
        use OpCode::*;
        match opcode {
            Continuation => {
                unreachable!("continuation should never be recieved when using a fragmentcollector")
            }
            Text => Self::Text,
            Binary => Self::Binary,
            Close => Self::Close,
            Ping => Self::Ping,
            Pong => Self::Pong,
        }
    }
}

impl From<Frame<'_>> for crate::ws::Frame {
    fn from(mut frame: Frame) -> Self {
        Self {
            finished: frame.fin,
            opcode: frame.opcode.into(),
            payload: Bytes::copy_from_slice(frame.payload.to_mut()),
        }
    }
}

impl From<crate::ws::Frame> for Frame<'_> {
    fn from(frame: crate::ws::Frame) -> Self {
        use crate::ws::OpCode::*;
        match frame.opcode {
            Text => Self::text(Payload::Owned(frame.payload.to_vec())),
            Binary => Self::binary(Payload::Owned(frame.payload.to_vec())),
            Close => Self::close_raw(Payload::Owned(frame.payload.to_vec())),
            Ping => Self::new(
                true,
                OpCode::Ping,
                None,
                Payload::Owned(frame.payload.to_vec()),
            ),
            Pong => Self::pong(Payload::Owned(frame.payload.to_vec())),
        }
    }
}

impl From<WebSocketError> for crate::WispError {
    fn from(err: WebSocketError) -> Self {
        if let WebSocketError::ConnectionClosed = err {
            Self::WsImplSocketClosed
        } else {
            Self::WsImplError(Box::new(err))
        }
    }
}

#[async_trait]
impl<S: AsyncRead + Unpin + Send> crate::ws::WebSocketRead for FragmentCollectorRead<S> {
    async fn wisp_read_frame(
        &mut self,
        tx: &LockedWebSocketWrite,
    ) -> Result<crate::ws::Frame, WispError> {
        Ok(self
            .read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
            .await?
            .into())
    }
}

#[async_trait]
impl<S: AsyncWrite + Unpin + Send> crate::ws::WebSocketWrite for WebSocketWrite<S> {
    async fn wisp_write_frame(&mut self, frame: crate::ws::Frame) -> Result<(), WispError> {
        self.write_frame(frame.into()).await.map_err(|e| e.into())
    }
}
