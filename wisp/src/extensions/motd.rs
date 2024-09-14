//! MOTD protocol extension.
//!
//! See [the
//! docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x04---server-motd)
use async_trait::async_trait;
use bytes::Bytes;

use crate::{
	ws::{LockedWebSocketWrite, WebSocketRead},
	Role, WispError,
};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

#[derive(Debug, Clone)]
/// MOTD protocol extension.
pub struct MotdProtocolExtension {
	role: Role,
	/// MOTD from server, or an empty string.
	pub motd: String,
}

impl MotdProtocolExtension {
	/// MOTD protocol extension ID.
	pub const ID: u8 = 0x04;
}

#[async_trait]
impl ProtocolExtension for MotdProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		&[]
	}

	fn get_congestion_stream_types(&self) -> &'static [u8] {
		&[]
	}

	fn encode(&self) -> Bytes {
		match self.role {
			Role::Server => Bytes::from(self.motd.as_bytes().to_vec()),
			Role::Client => Bytes::new(),
		}
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
		Box::new(self.clone())
	}
}

impl From<MotdProtocolExtension> for AnyProtocolExtension {
	fn from(value: MotdProtocolExtension) -> Self {
		AnyProtocolExtension(Box::new(value))
	}
}

/// MOTD protocol extension builder.
pub enum MotdProtocolExtensionBuilder {
	/// Server variant of MOTD protocol extension builder. Has the MOTD.
	Server(String),
	/// Client variant of MOTD protocol extension builder.
	Client,
}

impl ProtocolExtensionBuilder for MotdProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		MotdProtocolExtension::ID
	}

	fn build_from_bytes(
		&mut self,
		data: Bytes,
		role: crate::Role,
	) -> Result<AnyProtocolExtension, WispError> {
		Ok(match role {
			Role::Client => MotdProtocolExtension {
				role,
				motd: String::from_utf8(data.to_vec())
					.map_err(|x| WispError::ExtensionImplError(Box::new(x)))?,
			},
			Role::Server => MotdProtocolExtension {
				role,
				motd: String::new(),
			},
		}
		.into())
	}

	fn build_to_extension(&mut self, role: crate::Role) -> Result<AnyProtocolExtension, WispError> {
		Ok(match self {
			Self::Server(motd) => MotdProtocolExtension {
				role,
				motd: motd.clone(),
			},
			Self::Client => MotdProtocolExtension {
				role,
				motd: String::new(),
			},
		}
		.into())
	}
}
