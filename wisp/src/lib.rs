#[cfg(feature = "fastwebsockets")]
mod fastwebsockets;
mod packet;
pub mod ws;

pub use crate::packet::*;

#[derive(Debug, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug)]
pub enum WispError {
    PacketTooSmall,
    InvalidPacketType,
    WsFrameInvalidType,
    WsFrameNotFinished,
    WsImplError(Box<dyn std::error::Error>),
    WsImplNotSupported,
    Utf8Error(std::str::Utf8Error),
}

impl From<std::str::Utf8Error> for WispError {
    fn from(err: std::str::Utf8Error) -> WispError {
        WispError::Utf8Error(err)
    }
}

impl std::fmt::Display for WispError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use WispError::*;
        match self {
            PacketTooSmall => write!(f, "Packet too small"),
            InvalidPacketType => write!(f, "Invalid packet type"),
            WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
            WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
            WsImplError(err) => write!(f, "Websocket implementation error: {:?}", err),
            WsImplNotSupported => write!(f, "Websocket implementation error: unsupported feature"),
            Utf8Error(err) => write!(f, "UTF-8 error: {:?}", err),
        }
    }
}

impl std::error::Error for WispError {}
