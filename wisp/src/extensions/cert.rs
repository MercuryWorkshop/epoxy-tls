//! Certificate authentication protocol extension.
//!

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519::{
	signature::{Signer, Verifier},
	Signature,
};

use crate::{
	ws::{LockedWebSocketWrite, WebSocketRead},
	Role, WispError,
};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

/// Certificate authentication protocol extension error.
#[derive(Debug)]
pub enum CertAuthError {
	/// ED25519 error
	Ed25519(ed25519::Error),
	/// Getrandom error
	Getrandom(getrandom::Error),
}

impl std::fmt::Display for CertAuthError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Ed25519(x) => write!(f, "ED25519: {:?}", x),
			Self::Getrandom(x) => write!(f, "getrandom: {:?}", x),
		}
	}
}
impl std::error::Error for CertAuthError {}

impl From<ed25519::Error> for CertAuthError {
	fn from(value: ed25519::Error) -> Self {
		CertAuthError::Ed25519(value)
	}
}
impl From<getrandom::Error> for CertAuthError {
	fn from(value: getrandom::Error) -> Self {
		CertAuthError::Getrandom(value)
	}
}
impl From<CertAuthError> for WispError {
	fn from(value: CertAuthError) -> Self {
		WispError::ExtensionImplError(Box::new(value))
	}
}

bitflags::bitflags! {
	/// Supported certificate types for certificate authentication.
	#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
	pub struct SupportedCertificateTypes: u8 {
		/// ED25519 certificate.
		const Ed25519 = 0b00000001;
	}
}

/// Verification key.
#[derive(Clone)]
pub struct VerifyKey {
	/// Certificate type of the keypair.
	pub cert_type: SupportedCertificateTypes,
	/// SHA-512 hash of the public key.
	pub hash: [u8; 64],
	/// Verifier.
	pub verifier: Arc<dyn Verifier<Signature>>,
}

impl VerifyKey {
	/// Create a new ED25519 verification key.
	pub fn new_ed25519(verifier: Arc<dyn Verifier<Signature>>, hash: [u8; 64]) -> Self {
		Self {
			cert_type: SupportedCertificateTypes::Ed25519,
			hash,
			verifier,
		}
	}
}

/// Signing key.
#[derive(Clone)]
pub struct SigningKey {
	/// Certificate type of the keypair.
	pub cert_type: SupportedCertificateTypes,
	/// SHA-512 hash of the public key.
	pub hash: [u8; 64],
	/// Signer.
	pub signer: Arc<dyn Signer<Signature>>,
}
impl SigningKey {
	/// Create a new ED25519 signing key.
	pub fn new_ed25519(signer: Arc<dyn Signer<Signature>>, hash: [u8; 64]) -> Self {
		Self {
			cert_type: SupportedCertificateTypes::Ed25519,
			hash,
			signer,
		}
	}
}

/// Certificate authentication protocol extension.
#[derive(Debug, Clone)]
pub enum CertAuthProtocolExtension {
	/// Server variant of certificate authentication protocol extension.
	Server {
		/// Supported certificate types on the server.
		cert_types: SupportedCertificateTypes,
		/// Random challenge for the client.
		challenge: Bytes,
	},
	/// Client variant of certificate authentication protocol extension.
	Client {
		/// Chosen certificate type.
		cert_type: SupportedCertificateTypes,
		/// Hash of public key.
		hash: [u8; 64],
		/// Signature of challenge.
		signature: Bytes,
	},
	/// Marker that client has successfully signed the challenge.
	ClientSigned,
	/// Marker that server has successfully verified the client.
	ServerVerified,
}

impl CertAuthProtocolExtension {
	/// ID of certificate authentication protocol extension.
	pub const ID: u8 = 0x03;
}

#[async_trait]
impl ProtocolExtension for CertAuthProtocolExtension {
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
		match self {
			Self::Server {
				cert_types,
				challenge,
			} => {
				let mut out = BytesMut::with_capacity(1 + challenge.len());
				out.put_u8(cert_types.bits());
				out.extend_from_slice(challenge);
				out.freeze()
			}
			Self::Client {
				cert_type,
				hash,
				signature,
			} => {
				let mut out = BytesMut::with_capacity(1 + signature.len());
				out.put_u8(cert_type.bits());
				out.extend_from_slice(hash);
				out.extend_from_slice(signature);
				out.freeze()
			}
			Self::ClientSigned => Bytes::new(),
			Self::ServerVerified => Bytes::new(),
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

impl From<CertAuthProtocolExtension> for AnyProtocolExtension {
	fn from(value: CertAuthProtocolExtension) -> Self {
		AnyProtocolExtension(Box::new(value))
	}
}

/// Certificate authentication protocol extension builder.
pub enum CertAuthProtocolExtensionBuilder {
	/// Server variant of certificate authentication protocol extension before the challenge has
	/// been sent.
	ServerBeforeChallenge {
		/// Keypair verifiers.
		verifiers: Vec<VerifyKey>,
	},
	/// Server variant of certificate authentication protocol extension after the challenge has
	/// been sent.
	ServerAfterChallenge {
		/// Keypair verifiers.
		verifiers: Vec<VerifyKey>,
		/// Challenge to verify against.
		challenge: Bytes,
	},
	/// Client variant of certificate authentication protocol extension before the challenge has
	/// been recieved.
	ClientBeforeChallenge {
		/// Keypair signer.
		signer: SigningKey,
	},
	/// Client variant of certificate authentication protocol extension after the challenge has
	/// been recieved.
	ClientAfterChallenge {
		/// Keypair signer.
		signer: SigningKey,
		/// Signature of challenge recieved from the server.
		signature: Bytes,
	},
}

#[async_trait]
impl ProtocolExtensionBuilder for CertAuthProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		CertAuthProtocolExtension::ID
	}

	// client: 1
	// server: 2
	fn build_from_bytes(
		&mut self,
		mut bytes: Bytes,
		_: Role,
	) -> Result<AnyProtocolExtension, WispError> {
		match self {
			// server should have already sent the challenge before recieving a response to parse
			Self::ServerBeforeChallenge { .. } => Err(WispError::ExtensionImplNotSupported),
			Self::ServerAfterChallenge {
				verifiers,
				challenge,
			} => {
				// validate and parse response
				let cert_type = SupportedCertificateTypes::from_bits(bytes.get_u8())
					.ok_or(WispError::CertAuthExtensionSigInvalid)?;
				let hash = bytes.split_to(64);
				let sig = Signature::from_slice(&bytes).map_err(CertAuthError::from)?;
				let is_valid = verifiers
					.iter()
					.filter(|x| x.cert_type == cert_type && x.hash == *hash)
					.any(|x| x.verifier.verify(challenge, &sig).is_ok());

				if is_valid {
					Ok(CertAuthProtocolExtension::ServerVerified.into())
				} else {
					Err(WispError::CertAuthExtensionSigInvalid)
				}
			}
			Self::ClientBeforeChallenge { signer } => {
				// sign challenge
				let cert_types = SupportedCertificateTypes::from_bits(bytes.get_u8())
					.ok_or(WispError::CertAuthExtensionSigInvalid)?;
				if !cert_types.iter().any(|x| x == signer.cert_type) {
					return Err(WispError::CertAuthExtensionSigInvalid);
				}

				let signed: Bytes = signer
					.signer
					.try_sign(&bytes)
					.map_err(CertAuthError::from)?
					.to_vec()
					.into();

				*self = Self::ClientAfterChallenge {
					signer: signer.clone(),
					signature: signed,
				};

				Ok(CertAuthProtocolExtension::ClientSigned.into())
			}
			// client has already recieved a challenge
			Self::ClientAfterChallenge { .. } => Err(WispError::ExtensionImplNotSupported),
		}
	}

	// client: 2
	// server: 1
	fn build_to_extension(&mut self, _: Role) -> Result<AnyProtocolExtension, WispError> {
		match self {
			Self::ServerBeforeChallenge { verifiers } => {
				let mut challenge = BytesMut::with_capacity(64);
				getrandom::getrandom(&mut challenge).map_err(CertAuthError::from)?;
				let challenge = challenge.freeze();

				*self = Self::ServerAfterChallenge {
					verifiers: verifiers.to_vec(),
					challenge: challenge.clone(),
				};

				Ok(CertAuthProtocolExtension::Server {
					cert_types: SupportedCertificateTypes::Ed25519,
					challenge,
				}
				.into())
			}
			// server has already sent a challenge
			Self::ServerAfterChallenge { .. } => Err(WispError::ExtensionImplNotSupported),
			// client needs to recieve a challenge
			Self::ClientBeforeChallenge { .. } => Err(WispError::ExtensionImplNotSupported),
			Self::ClientAfterChallenge { signer, signature } => {
				Ok(CertAuthProtocolExtension::Client {
					cert_type: signer.cert_type,
					hash: signer.hash,
					signature: signature.clone(),
				}
				.into())
			}
		}
	}
}
