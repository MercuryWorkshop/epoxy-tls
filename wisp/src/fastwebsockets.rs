use bytes::Bytes;
use fastwebsockets::{Payload, Frame, OpCode};

impl TryFrom<OpCode> for crate::ws::OpCode {
    type Error = crate::WispError;
    fn try_from(opcode: OpCode) -> Result<Self, Self::Error> {
        use OpCode::*;
        match opcode {
            Continuation => Err(Self::Error::WsImplNotSupported),
            Text => Ok(Self::Text),
            Binary => Ok(Self::Binary),
            Close => Ok(Self::Close),
            Ping => Err(Self::Error::WsImplNotSupported),
            Pong => Err(Self::Error::WsImplNotSupported),
        }
    }
}

impl TryFrom<Frame<'_>> for crate::ws::Frame {
    type Error = crate::WispError;
    fn try_from(mut frame: Frame) -> Result<Self, Self::Error> {
        let opcode = frame.opcode.try_into()?;
        Ok(Self {
            finished: frame.fin,
            opcode,
            payload: Bytes::copy_from_slice(frame.payload.to_mut()),
        })
    }
}

impl From<crate::ws::Frame> for Frame<'_> {
    fn from(frame: crate::ws::Frame) -> Self {
        use crate::ws::OpCode::*;
        match frame.opcode {
            Text => Self::text(Payload::Owned(frame.payload.to_vec())),
            Binary => Self::binary(Payload::Owned(frame.payload.to_vec())),
            Close => Self::close_raw(Payload::Owned(frame.payload.to_vec()))
        }
    }
}
