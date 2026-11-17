#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::error::Error;

use packet::WispVersion;
use thiserror::Error as ErrorDerive;

pub mod extensions;
mod locked_sink;
mod waiters;
mod mux;
pub mod packet;
pub mod stream;
pub mod timer;
pub mod ws;

pub use mux::*;

use locked_sink::LockedWebSocketWrite;
pub use locked_sink::{LockedSinkGuard, LockedWebSocketWriteGuard};

pub const WISP_VERSION: WispVersion = WispVersion { major: 2, minor: 0 };

#[derive(Debug, ErrorDerive)]
pub enum WispError {
	/// Stream ID was invalid.
	#[error("Invalid stream ID: {0}")]
	InvalidStreamId(u32),
	/// Packet type was invalid.
	#[error("Invalid packet type: {0:#02X}")]
	InvalidPacketType(u8),
	/// Packet was too small.
	#[error("Packet too small")]
	PacketTooSmall,
	/// The Wisp protocol version was incompatible.
	#[error("Incompatible Wisp protocol version: found {0} but needed {1}")]
	IncompatibleProtocolVersion(WispVersion, WispVersion),
	/// The Wisp handshake timed out.
	#[error("Handshake timed out")]
	HandshakeTimedOut,

	/// The stream was closed already.
	#[error("Stream already closed")]
	StreamAlreadyClosed,
	/// The max stream count was reached.
	#[error("Maximum stream count reached")]
	MaxStreamCountReached,

	/// Failed to parse bytes as UTF-8.
	#[error("Invalid UTF-8: {0}")]
	Utf8(#[from] std::str::Utf8Error),
	#[error("Integer conversion error: {0}")]
	TryFromIntError(#[from] std::num::TryFromIntError),

	/// Failed to send message to multiplexor task.
	#[error("Failed to send multiplexor message")]
	MuxMessageFailedToSend,
	/// Failed to receive message from multiplexor task.
	#[error("Failed to receive multiplexor message")]
	MuxMessageFailedToRecv,
	/// Multiplexor task ended.
	#[error("Multiplexor task ended")]
	MuxTaskEnded,
	/// Multiplexor task already started.
	#[error("Multiplexor task already started")]
	MuxTaskStarted,

	/// Error specific to the websocket implementation.
	#[error("Websocket implementation error: {0}")]
	WsImplError(Box<dyn Error + Sync + Send>),
	/// Websocket implementation: websocket closed
	#[error("Websocket implementation error: websocket closed")]
	WsImplSocketClosed,

	/// Error specific to the protocol extension implementation.
	#[error("Protocol extension implementation error: {0:?}")]
	ExtensionImplError(Box<dyn std::error::Error + Sync + Send>),
	/// The protocol extension implementation did not support the action.
	#[error("Protocol extension implementation error: unsupported feature")]
	ExtensionImplNotSupported,
	/// The specified protocol extensions are not supported by the other side.
	#[error("Protocol extensions {0:?} not supported")]
	ExtensionsNotSupported(Vec<u8>),

	/// The password authentication username/password was invalid.
	#[error("Password protocol extension: Invalid username/password")]
	PasswordExtensionCredsInvalid,
	/// No password authentication username/password was provided.
	#[error("Password protocol extension: No username/password provided")]
	PasswordExtensionNoCreds,

	/// The certificate authentication certificate type was unsupported.
	#[error("Certificate authentication protocol extension: Invalid certificate type")]
	CertAuthExtensionCertTypeInvalid,
	/// The certificate authentication signature was invalid.
	#[error("Certificate authentication protocol extension: Invalid signature")]
	CertAuthExtensionSigInvalid,
	/// No certificate authentication signing key was provided.
	#[error("Password protocol extension: No signing key provided")]
	CertAuthExtensionNoKey,
}

impl From<std::string::FromUtf8Error> for WispError {
	fn from(value: std::string::FromUtf8Error) -> Self {
		Self::Utf8(value.utf8_error())
	}
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Role {
	Server,
	Client,
}
