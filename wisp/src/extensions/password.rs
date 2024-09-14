//! Password protocol extension.
//!
//! Passwords are sent in plain text!!
//!
//! See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)

use std::{collections::HashMap, error::Error, fmt::Display, string::FromUtf8Error};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
	ws::{LockedWebSocketWrite, WebSocketRead},
	Role, WispError,
};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

#[derive(Debug, Clone)]
/// Password protocol extension.
///
/// **Passwords are sent in plain text!!**
/// **This extension will panic when encoding if the username's length does not fit within a u8
/// or the password's length does not fit within a u16.**
pub struct PasswordProtocolExtension {
	/// The username to log in with.
	///
	/// This string's length must fit within a u8.
	pub username: String,
	/// The password to log in with.
	///
	/// This string's length must fit within a u16.
	pub password: String,
	role: Role,
}

impl PasswordProtocolExtension {
	/// Password protocol extension ID.
	pub const ID: u8 = 0x02;

	/// Create a new password protocol extension for the server.
	///
	/// This signifies that the server requires a password.
	pub fn new_server() -> Self {
		Self {
			username: String::new(),
			password: String::new(),
			role: Role::Server,
		}
	}

	/// Create a new password protocol extension for the client, with a username and password.
	///
	/// The username's length must fit within a u8. The password's length must fit within a
	/// u16.
	pub fn new_client(username: String, password: String) -> Self {
		Self {
			username,
			password,
			role: Role::Client,
		}
	}
}

#[async_trait]
impl ProtocolExtension for PasswordProtocolExtension {
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
			Role::Server => Bytes::new(),
			Role::Client => {
				let username = Bytes::from(self.username.clone().into_bytes());
				let password = Bytes::from(self.password.clone().into_bytes());
				let username_len = u8::try_from(username.len()).expect("username was too long");
				let password_len = u16::try_from(password.len()).expect("password was too long");

				let mut bytes =
					BytesMut::with_capacity(3 + username_len as usize + password_len as usize);
				bytes.put_u8(username_len);
				bytes.put_u16_le(password_len);
				bytes.extend(username);
				bytes.extend(password);
				bytes.freeze()
			}
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

#[derive(Debug)]
enum PasswordProtocolExtensionError {
	Utf8Error(FromUtf8Error),
	InvalidUsername,
	InvalidPassword,
}

impl Display for PasswordProtocolExtensionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use PasswordProtocolExtensionError as E;
		match self {
			E::Utf8Error(e) => write!(f, "{}", e),
			E::InvalidUsername => write!(f, "Invalid username"),
			E::InvalidPassword => write!(f, "Invalid password"),
		}
	}
}

impl Error for PasswordProtocolExtensionError {}

impl From<PasswordProtocolExtensionError> for WispError {
	fn from(value: PasswordProtocolExtensionError) -> Self {
		WispError::ExtensionImplError(Box::new(value))
	}
}

impl From<FromUtf8Error> for PasswordProtocolExtensionError {
	fn from(value: FromUtf8Error) -> Self {
		PasswordProtocolExtensionError::Utf8Error(value)
	}
}

impl From<PasswordProtocolExtension> for AnyProtocolExtension {
	fn from(value: PasswordProtocolExtension) -> Self {
		AnyProtocolExtension(Box::new(value))
	}
}

/// Password protocol extension builder.
///
/// **Passwords are sent in plain text!!**
pub struct PasswordProtocolExtensionBuilder {
	/// Map of users and their passwords to allow. Only used on server.
	pub users: HashMap<String, String>,
	/// Username to authenticate with. Only used on client.
	pub username: String,
	/// Password to authenticate with. Only used on client.
	pub password: String,
}

impl PasswordProtocolExtensionBuilder {
	/// Create a new password protocol extension builder for the server, with a map of users
	/// and passwords to allow.
	pub fn new_server(users: HashMap<String, String>) -> Self {
		Self {
			users,
			username: String::new(),
			password: String::new(),
		}
	}

	/// Create a new password protocol extension builder for the client, with a username and
	/// password to authenticate with.
	pub fn new_client(username: String, password: String) -> Self {
		Self {
			users: HashMap::new(),
			username,
			password,
		}
	}
}

impl ProtocolExtensionBuilder for PasswordProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		PasswordProtocolExtension::ID
	}

	fn build_from_bytes(
		&mut self,
		mut payload: Bytes,
		role: crate::Role,
	) -> Result<AnyProtocolExtension, WispError> {
		match role {
			Role::Server => {
				if payload.remaining() < 3 {
					return Err(WispError::PacketTooSmall);
				}

				let username_len = payload.get_u8();
				let password_len = payload.get_u16_le();
				if payload.remaining() < (password_len + username_len as u16) as usize {
					return Err(WispError::PacketTooSmall);
				}

				use PasswordProtocolExtensionError as EError;
				let username =
					String::from_utf8(payload.copy_to_bytes(username_len as usize).to_vec())
						.map_err(|x| WispError::from(EError::from(x)))?;
				let password =
					String::from_utf8(payload.copy_to_bytes(password_len as usize).to_vec())
						.map_err(|x| WispError::from(EError::from(x)))?;

				let Some(user) = self.users.iter().find(|x| *x.0 == username) else {
					return Err(EError::InvalidUsername.into());
				};

				if *user.1 != password {
					return Err(EError::InvalidPassword.into());
				}

				Ok(PasswordProtocolExtension {
					username,
					password,
					role,
				}
				.into())
			}
			Role::Client => {
				Ok(PasswordProtocolExtension::new_client(String::new(), String::new()).into())
			}
		}
	}

	fn build_to_extension(&mut self, role: Role) -> Result<AnyProtocolExtension, WispError> {
		Ok(match role {
			Role::Server => PasswordProtocolExtension::new_server(),
			Role::Client => {
				PasswordProtocolExtension::new_client(self.username.clone(), self.password.clone())
			}
		}
		.into())
	}
}
