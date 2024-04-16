use std::ops::Deref;

use async_trait::async_trait;
use bytes::BytesMut;
use fastwebsockets::{
    CloseCode, FragmentCollectorRead, Frame, OpCode, Payload, WebSocketError, WebSocketWrite
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
    fn from(frame: Frame) -> Self {
        Self {
            finished: frame.fin,
            opcode: frame.opcode.into(),
            payload: BytesMut::from(frame.payload.deref()).freeze(),
        }
    }
}

impl<'a> From<crate::ws::Frame> for Frame<'a> {
    fn from(frame: crate::ws::Frame) -> Self {
        use crate::ws::OpCode::*;
        let payload = Payload::Owned(frame.payload.into());
        match frame.opcode {
            Text => Self::text(payload),
            Binary => Self::binary(payload),
            Close => Self::close_raw(payload),
            Ping => Self::new(true, OpCode::Ping, None, payload),
            Pong => Self::pong(payload),
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

    async fn wisp_close(&mut self) -> Result<(), WispError> {
        self.write_frame(Frame::close(CloseCode::Normal.into(), b"")).await.map_err(|e| e.into())
    }
}
