use futures::{SinkExt, StreamExt};
use ws_stream_wasm::{WsErr, WsMessage, WsStream};

impl From<WsMessage> for crate::ws::Frame {
    fn from(msg: WsMessage) -> Self {
        use crate::ws::OpCode;
        match msg {
            WsMessage::Text(str) => Self {
                finished: true,
                opcode: OpCode::Text,
                payload: str.into(),
            },
            WsMessage::Binary(bin) => Self {
                finished: true,
                opcode: OpCode::Binary,
                payload: bin.into(),
            },
        }
    }
}

impl TryFrom<crate::ws::Frame> for WsMessage {
    type Error = crate::WispError;
    fn try_from(msg: crate::ws::Frame) -> Result<Self, Self::Error> {
        use crate::ws::OpCode;
        match msg.opcode {
            OpCode::Text => Ok(Self::Text(std::str::from_utf8(&msg.payload)?.to_string())),
            OpCode::Binary => Ok(Self::Binary(msg.payload.to_vec())),
            _ => Err(Self::Error::WsImplNotSupported),
        }
    }
}

impl From<WsErr> for crate::WispError {
    fn from(err: WsErr) -> Self {
        Self::WsImplError(Box::new(err))
    }
}

impl crate::ws::WebSocketRead for WsStream {
    async fn wisp_read_frame(
        &mut self,
        _: &mut crate::ws::LockedWebSocketWrite<impl crate::ws::WebSocketWrite>,
    ) -> Result<crate::ws::Frame, crate::WispError> {
        Ok(self
            .next()
            .await
            .ok_or(crate::WispError::WsImplSocketClosed)?
            .into())
    }
}

impl crate::ws::WebSocketWrite for WsStream {
    async fn wisp_write_frame(&mut self, frame: crate::ws::Frame) -> Result<(), crate::WispError> {
        self.send(frame.try_into()?).await.map_err(|e| e.into())
    }
}
