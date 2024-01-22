mod packet;
mod ws;

pub use crate::packet::*;

#[derive(Debug, PartialEq)]
pub enum Role {
    Client,
    Server,
}

pub enum WispError {
    PacketTooSmall,
    InvalidPacketType,
    WsFrameInvalidType,
    WsFrameNotFinished,
    WsImplError(Box<dyn std::error::Error>),
    Utf8Error(std::str::Utf8Error),
}

impl From<std::str::Utf8Error> for WispError {
    fn from(err: std::str::Utf8Error) -> WispError {
        WispError::Utf8Error(err)
    }
}
