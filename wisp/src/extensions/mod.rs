//! Wisp protocol extensions.
pub mod password;
pub mod udp;
pub mod motd;
#[cfg(feature = "certificate")]
pub mod cert;

use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};

use crate::{
	ws::{LockedWebSocketWrite, WebSocketRead},
	Role, WispError,
};

/// Type-erased protocol extension that implements Clone.
#[derive(Debug)]
pub struct AnyProtocolExtension(Box<dyn ProtocolExtension + Sync + Send>);

impl AnyProtocolExtension {
	/// Create a new type-erased protocol extension.
	pub fn new<T: ProtocolExtension + Sync + Send + 'static>(extension: T) -> Self {
		Self(Box::new(extension))
	}
}

impl Deref for AnyProtocolExtension {
	type Target = dyn ProtocolExtension;
	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

impl DerefMut for AnyProtocolExtension {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.0.deref_mut()
	}
}

impl Clone for AnyProtocolExtension {
	fn clone(&self) -> Self {
		Self(self.0.box_clone())
	}
}

impl From<AnyProtocolExtension> for Bytes {
	fn from(value: AnyProtocolExtension) -> Self {
		let mut bytes = BytesMut::with_capacity(5);
		let payload = value.encode();
		bytes.put_u8(value.get_id());
		bytes.put_u32_le(payload.len() as u32);
		bytes.extend(payload);
		bytes.freeze()
	}
}

/// A Wisp protocol extension.
///
/// See [the
/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#protocol-extensions).
#[async_trait]
pub trait ProtocolExtension: std::fmt::Debug {
	/// Get the protocol extension ID.
	fn get_id(&self) -> u8;
	/// Get the protocol extension's supported packets.
	///
	/// Used to decide whether to call the protocol extension's packet handler.
	fn get_supported_packets(&self) -> &'static [u8];
	/// Get stream types that should be treated as TCP.
	///
	/// Used to decide whether to handle congestion control for that stream type.
	fn get_congestion_stream_types(&self) -> &'static [u8];

	/// Encode self into Bytes.
	fn encode(&self) -> Bytes;

	/// Handle the handshake part of a Wisp connection.
	///
	/// This should be used to send or receive data before any streams are created.
	async fn handle_handshake(
		&mut self,
		read: &mut dyn WebSocketRead,
		write: &LockedWebSocketWrite,
	) -> Result<(), WispError>;

	/// Handle receiving a packet.
	async fn handle_packet(
		&mut self,
		packet: Bytes,
		read: &mut dyn WebSocketRead,
		write: &LockedWebSocketWrite,
	) -> Result<(), WispError>;

	/// Clone the protocol extension.
	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send>;
}

/// Trait to build a Wisp protocol extension from a payload.
pub trait ProtocolExtensionBuilder {
	/// Get the protocol extension ID.
	///
	/// Used to decide whether this builder should be used.
	fn get_id(&self) -> u8;

	/// Build a protocol extension from the extension's metadata.
	fn build_from_bytes(&mut self, bytes: Bytes, role: Role)
		-> Result<AnyProtocolExtension, WispError>;

	/// Build a protocol extension to send to the other side.
	fn build_to_extension(&mut self, role: Role) -> Result<AnyProtocolExtension, WispError>;
}
