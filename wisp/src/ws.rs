use bytes::Bytes;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
    Text,
    Binary,
    Close,
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
