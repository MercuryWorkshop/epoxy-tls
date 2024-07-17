//! UDP protocol extension.
//!
//! # Example
//! ```
//! let (mux, fut) = ServerMux::new(
//!     rx,
//!     tx,
//!     128,
//!     Some(&[Box::new(UdpProtocolExtensionBuilder)])
//! );
//! ```
//! See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x01---udp)
use async_trait::async_trait;
use bytes::Bytes;

use crate::{
	ws::{LockedWebSocketWrite, WebSocketRead},
	WispError,
};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

#[derive(Debug)]
/// UDP protocol extension.
pub struct UdpProtocolExtension;

impl UdpProtocolExtension {
	/// UDP protocol extension ID.
	pub const ID: u8 = 0x01;
}

#[async_trait]
impl ProtocolExtension for UdpProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		&[]
	}

	fn encode(&self) -> Bytes {
		Bytes::new()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		_: Bytes,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(Self)
	}
}

impl From<UdpProtocolExtension> for AnyProtocolExtension {
	fn from(value: UdpProtocolExtension) -> Self {
		AnyProtocolExtension(Box::new(value))
	}
}

/// UDP protocol extension builder.
pub struct UdpProtocolExtensionBuilder;

impl ProtocolExtensionBuilder for UdpProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		UdpProtocolExtension::ID
	}

	fn build_from_bytes(
		&self,
		_: Bytes,
		_: crate::Role,
	) -> Result<AnyProtocolExtension, WispError> {
		Ok(UdpProtocolExtension.into())
	}

	fn build_to_extension(&self, _: crate::Role) -> AnyProtocolExtension {
		UdpProtocolExtension.into()
	}
}
