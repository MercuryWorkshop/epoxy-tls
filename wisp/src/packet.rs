use crate::{
	extensions::{AnyProtocolExtension, AnyProtocolExtensionBuilder},
	ws::{self, Frame, LockedWebSocketWrite, OpCode, Payload, WebSocketRead},
	Role, WispError, WISP_VERSION,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Wisp stream type.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum StreamType {
	/// TCP Wisp stream.
	Tcp,
	/// UDP Wisp stream.
	Udp,
	/// Unknown Wisp stream type used for custom streams by protocol extensions.
	Unknown(u8),
}

impl From<u8> for StreamType {
	fn from(value: u8) -> Self {
		use StreamType as S;
		match value {
			0x01 => S::Tcp,
			0x02 => S::Udp,
			x => S::Unknown(x),
		}
	}
}

impl From<StreamType> for u8 {
	fn from(value: StreamType) -> Self {
		use StreamType as S;
		match value {
			S::Tcp => 0x01,
			S::Udp => 0x02,
			S::Unknown(x) => x,
		}
	}
}

mod close {
	use std::fmt::Display;

	use atomic_enum::atomic_enum;

	use crate::WispError;

	/// Close reason.
	///
	/// See [the
	/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#clientserver-close-reasons)
	#[derive(PartialEq)]
	#[repr(u8)]
	#[atomic_enum]
	pub enum CloseReason {
		/// Reason unspecified or unknown.
		Unknown = 0x01,
		/// Voluntary stream closure.
		Voluntary = 0x02,
		/// Unexpected stream closure due to a network error.
		Unexpected = 0x03,
		/// Incompatible extensions. Only used during the handshake.
		ExtensionsIncompatible = 0x04,
		/// Stream creation failed due to invalid information.
		ServerStreamInvalidInfo = 0x41,
		/// Stream creation failed due to an unreachable destination host.
		ServerStreamUnreachable = 0x42,
		/// Stream creation timed out due to the destination server not responding.
		ServerStreamConnectionTimedOut = 0x43,
		/// Stream creation failed due to the destination server refusing the connection.
		ServerStreamConnectionRefused = 0x44,
		/// TCP data transfer timed out.
		ServerStreamTimedOut = 0x47,
		/// Stream destination address/domain is intentionally blocked by the proxy server.
		ServerStreamBlockedAddress = 0x48,
		/// Connection throttled by the server.
		ServerStreamThrottled = 0x49,
		/// The client has encountered an unexpected error.
		ClientUnexpected = 0x81,
		/// Authentication failed due to invalid username/password.
		ExtensionsPasswordAuthFailed = 0xc0,
		/// Authentication failed due to invalid signature.
		ExtensionsCertAuthFailed = 0xc1,
	}

	impl TryFrom<u8> for CloseReason {
		type Error = WispError;
		fn try_from(close_reason: u8) -> Result<Self, Self::Error> {
			use CloseReason as R;
			match close_reason {
				0x01 => Ok(R::Unknown),
				0x02 => Ok(R::Voluntary),
				0x03 => Ok(R::Unexpected),
				0x04 => Ok(R::ExtensionsIncompatible),
				0x41 => Ok(R::ServerStreamInvalidInfo),
				0x42 => Ok(R::ServerStreamUnreachable),
				0x43 => Ok(R::ServerStreamConnectionTimedOut),
				0x44 => Ok(R::ServerStreamConnectionRefused),
				0x47 => Ok(R::ServerStreamTimedOut),
				0x48 => Ok(R::ServerStreamBlockedAddress),
				0x49 => Ok(R::ServerStreamThrottled),
				0x81 => Ok(R::ClientUnexpected),
				_ => Err(Self::Error::InvalidCloseReason),
			}
		}
	}

	impl Display for CloseReason {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			use CloseReason as C;
			write!(
				f,
				"{}",
				match self {
					C::Unknown => "Unknown close reason",
					C::Voluntary => "Voluntarily closed",
					C::Unexpected => "Unexpectedly closed",
					C::ExtensionsIncompatible => "Incompatible protocol extensions",
					C::ServerStreamInvalidInfo =>
						"Stream creation failed due to invalid information",
					C::ServerStreamUnreachable =>
						"Stream creation failed due to an unreachable destination",
					C::ServerStreamConnectionTimedOut =>
						"Stream creation failed due to destination not responding",
					C::ServerStreamConnectionRefused =>
						"Stream creation failed due to destination refusing connection",
					C::ServerStreamTimedOut => "TCP timed out",
					C::ServerStreamBlockedAddress => "Destination address is blocked",
					C::ServerStreamThrottled => "Throttled",
					C::ClientUnexpected => "Client encountered unexpected error",
					C::ExtensionsPasswordAuthFailed => "Invalid username/password",
					C::ExtensionsCertAuthFailed => "Invalid signature",
				}
			)
		}
	}
}

pub(crate) use close::AtomicCloseReason;
pub use close::CloseReason;

trait Encode {
	fn encode(self, bytes: &mut BytesMut);
}

/// Packet used to create a new stream.
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#0x01---connect).
#[derive(Debug, Clone)]
pub struct ConnectPacket {
	/// Whether the new stream should use a TCP or UDP socket.
	pub stream_type: StreamType,
	/// Destination TCP/UDP port for the new stream.
	pub destination_port: u16,
	/// Destination hostname, in a UTF-8 string.
	pub destination_hostname: String,
}

impl ConnectPacket {
	/// Create a new connect packet.
	pub fn new(
		stream_type: StreamType,
		destination_port: u16,
		destination_hostname: String,
	) -> Self {
		Self {
			stream_type,
			destination_port,
			destination_hostname,
		}
	}
}

impl TryFrom<Payload<'_>> for ConnectPacket {
	type Error = WispError;
	fn try_from(mut bytes: Payload<'_>) -> Result<Self, Self::Error> {
		if bytes.remaining() < (1 + 2) {
			return Err(Self::Error::PacketTooSmall);
		}
		Ok(Self {
			stream_type: bytes.get_u8().into(),
			destination_port: bytes.get_u16_le(),
			destination_hostname: std::str::from_utf8(&bytes)?.to_string(),
		})
	}
}

impl Encode for ConnectPacket {
	fn encode(self, bytes: &mut BytesMut) {
		bytes.put_u8(self.stream_type.into());
		bytes.put_u16_le(self.destination_port);
		bytes.extend(self.destination_hostname.bytes());
	}
}

/// Packet used for Wisp TCP stream flow control.
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#0x03---continue).
#[derive(Debug, Copy, Clone)]
pub struct ContinuePacket {
	/// Number of packets that the server can buffer for the current stream.
	pub buffer_remaining: u32,
}

impl ContinuePacket {
	/// Create a new continue packet.
	pub fn new(buffer_remaining: u32) -> Self {
		Self { buffer_remaining }
	}
}

impl TryFrom<Payload<'_>> for ContinuePacket {
	type Error = WispError;
	fn try_from(mut bytes: Payload<'_>) -> Result<Self, Self::Error> {
		if bytes.remaining() < 4 {
			return Err(Self::Error::PacketTooSmall);
		}
		Ok(Self {
			buffer_remaining: bytes.get_u32_le(),
		})
	}
}

impl Encode for ContinuePacket {
	fn encode(self, bytes: &mut BytesMut) {
		bytes.put_u32_le(self.buffer_remaining);
	}
}

/// Packet used to close a stream.
///
/// See [the
/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#0x04---close).
#[derive(Debug, Copy, Clone)]
pub struct ClosePacket {
	/// The close reason.
	pub reason: CloseReason,
}

impl ClosePacket {
	/// Create a new close packet.
	pub fn new(reason: CloseReason) -> Self {
		Self { reason }
	}
}

impl TryFrom<Payload<'_>> for ClosePacket {
	type Error = WispError;
	fn try_from(mut bytes: Payload<'_>) -> Result<Self, Self::Error> {
		if bytes.remaining() < 1 {
			return Err(Self::Error::PacketTooSmall);
		}
		Ok(Self {
			reason: bytes.get_u8().try_into()?,
		})
	}
}

impl Encode for ClosePacket {
	fn encode(self, bytes: &mut BytesMut) {
		bytes.put_u8(self.reason as u8);
	}
}

/// Wisp version sent in the handshake.
#[derive(Debug, Clone)]
pub struct WispVersion {
	/// Major Wisp version according to semver.
	pub major: u8,
	/// Minor Wisp version according to semver.
	pub minor: u8,
}

/// Packet used in the initial handshake.
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#0x05---info)
#[derive(Debug, Clone)]
pub struct InfoPacket {
	/// Wisp version sent in the packet.
	pub version: WispVersion,
	/// List of protocol extensions sent in the packet.
	pub extensions: Vec<AnyProtocolExtension>,
}

impl Encode for InfoPacket {
	fn encode(self, bytes: &mut BytesMut) {
		bytes.put_u8(self.version.major);
		bytes.put_u8(self.version.minor);
		for extension in self.extensions {
			bytes.extend_from_slice(&Bytes::from(extension));
		}
	}
}

#[derive(Debug, Clone)]
/// Type of packet recieved.
pub enum PacketType<'a> {
	/// Connect packet.
	Connect(ConnectPacket),
	/// Data packet.
	Data(Payload<'a>),
	/// Continue packet.
	Continue(ContinuePacket),
	/// Close packet.
	Close(ClosePacket),
	/// Info packet.
	Info(InfoPacket),
}

impl PacketType<'_> {
	/// Get the packet type used in the protocol.
	pub fn as_u8(&self) -> u8 {
		use PacketType as P;
		match self {
			P::Connect(_) => 0x01,
			P::Data(_) => 0x02,
			P::Continue(_) => 0x03,
			P::Close(_) => 0x04,
			P::Info(_) => 0x05,
		}
	}

	pub(crate) fn get_packet_size(&self) -> usize {
		use PacketType as P;
		match self {
			P::Connect(p) => 1 + 2 + p.destination_hostname.len(),
			P::Data(p) => p.len(),
			P::Continue(_) => 4,
			P::Close(_) => 1,
			P::Info(_) => 2,
		}
	}
}

impl Encode for PacketType<'_> {
	fn encode(self, bytes: &mut BytesMut) {
		use PacketType as P;
		match self {
			P::Connect(x) => x.encode(bytes),
			P::Data(x) => bytes.extend_from_slice(&x),
			P::Continue(x) => x.encode(bytes),
			P::Close(x) => x.encode(bytes),
			P::Info(x) => x.encode(bytes),
		};
	}
}

/// Wisp protocol packet.
#[derive(Debug, Clone)]
pub struct Packet<'a> {
	/// Stream this packet is associated with.
	pub stream_id: u32,
	/// Packet type recieved.
	pub packet_type: PacketType<'a>,
}

impl<'a> Packet<'a> {
	/// Create a new packet.
	///
	/// The helper functions should be used for most use cases.
	pub fn new(stream_id: u32, packet: PacketType<'a>) -> Self {
		Self {
			stream_id,
			packet_type: packet,
		}
	}

	/// Create a new connect packet.
	pub fn new_connect(
		stream_id: u32,
		stream_type: StreamType,
		destination_port: u16,
		destination_hostname: String,
	) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Connect(ConnectPacket::new(
				stream_type,
				destination_port,
				destination_hostname,
			)),
		}
	}

	/// Create a new data packet.
	pub fn new_data(stream_id: u32, data: Payload<'a>) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Data(data),
		}
	}

	/// Create a new continue packet.
	pub fn new_continue(stream_id: u32, buffer_remaining: u32) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Continue(ContinuePacket::new(buffer_remaining)),
		}
	}

	/// Create a new close packet.
	pub fn new_close(stream_id: u32, reason: CloseReason) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Close(ClosePacket::new(reason)),
		}
	}

	pub(crate) fn new_info(extensions: Vec<AnyProtocolExtension>) -> Self {
		Self {
			stream_id: 0,
			packet_type: PacketType::Info(InfoPacket {
				version: WISP_VERSION,
				extensions,
			}),
		}
	}

	fn parse_packet(packet_type: u8, mut bytes: Payload<'a>) -> Result<Self, WispError> {
		use PacketType as P;
		Ok(Self {
			stream_id: bytes.get_u32_le(),
			packet_type: match packet_type {
				0x01 => P::Connect(ConnectPacket::try_from(bytes)?),
				0x02 => P::Data(bytes),
				0x03 => P::Continue(ContinuePacket::try_from(bytes)?),
				0x04 => P::Close(ClosePacket::try_from(bytes)?),
				// 0x05 is handled seperately
				_ => return Err(WispError::InvalidPacketType),
			},
		})
	}

	fn parse_info(
		mut bytes: Payload<'a>,
		role: Role,
		extension_builders: &mut [AnyProtocolExtensionBuilder],
	) -> Result<Self, WispError> {
		// packet type is already read by code that calls this
		if bytes.remaining() < 4 + 2 {
			return Err(WispError::PacketTooSmall);
		}
		if bytes.get_u32_le() != 0 {
			return Err(WispError::InvalidStreamId);
		}

		let version = WispVersion {
			major: bytes.get_u8(),
			minor: bytes.get_u8(),
		};

		if version.major != WISP_VERSION.major {
			return Err(WispError::IncompatibleProtocolVersion);
		}

		let mut extensions = Vec::new();

		while bytes.remaining() > 4 {
			// We have some extensions
			let id = bytes.get_u8();
			let length = usize::try_from(bytes.get_u32_le())?;
			if bytes.remaining() < length {
				return Err(WispError::PacketTooSmall);
			}
			if let Some(builder) = extension_builders.iter_mut().find(|x| x.get_id() == id) {
				extensions.push(builder.build_from_bytes(bytes.copy_to_bytes(length), role)?)
			} else {
				bytes.advance(length)
			}
		}

		Ok(Self {
			stream_id: 0,
			packet_type: PacketType::Info(InfoPacket {
				version,
				extensions,
			}),
		})
	}

	pub(crate) fn maybe_parse_info(
		frame: Frame<'a>,
		role: Role,
		extension_builders: &mut [AnyProtocolExtensionBuilder],
	) -> Result<Self, WispError> {
		if !frame.finished {
			return Err(WispError::WsFrameNotFinished);
		}
		if frame.opcode != OpCode::Binary {
			return Err(WispError::WsFrameInvalidType);
		}
		let mut bytes = frame.payload;
		if bytes.remaining() < 1 {
			return Err(WispError::PacketTooSmall);
		}
		let packet_type = bytes.get_u8();
		if packet_type == 0x05 {
			Self::parse_info(bytes, role, extension_builders)
		} else {
			Self::parse_packet(packet_type, bytes)
		}
	}

	pub(crate) async fn maybe_handle_extension(
		frame: Frame<'a>,
		extensions: &mut [AnyProtocolExtension],
		read: &mut (dyn WebSocketRead + Send),
		write: &LockedWebSocketWrite,
	) -> Result<Option<Self>, WispError> {
		if !frame.finished {
			return Err(WispError::WsFrameNotFinished);
		}
		if frame.opcode != OpCode::Binary {
			return Err(WispError::WsFrameInvalidType);
		}
		let mut bytes = frame.payload;
		if bytes.remaining() < 5 {
			return Err(WispError::PacketTooSmall);
		}
		let packet_type = bytes.get_u8();
		match packet_type {
			0x01 => Ok(Some(Self {
				stream_id: bytes.get_u32_le(),
				packet_type: PacketType::Connect(bytes.try_into()?),
			})),
			0x02 => Ok(Some(Self {
				stream_id: bytes.get_u32_le(),
				packet_type: PacketType::Data(bytes),
			})),
			0x03 => Ok(Some(Self {
				stream_id: bytes.get_u32_le(),
				packet_type: PacketType::Continue(bytes.try_into()?),
			})),
			0x04 => Ok(Some(Self {
				stream_id: bytes.get_u32_le(),
				packet_type: PacketType::Close(bytes.try_into()?),
			})),
			0x05 => Ok(None),
			packet_type => {
				if let Some(extension) = extensions
					.iter_mut()
					.find(|x| x.get_supported_packets().iter().any(|x| *x == packet_type))
				{
					extension
						.handle_packet(BytesMut::from(bytes).freeze(), read, write)
						.await?;
					Ok(None)
				} else {
					Err(WispError::InvalidPacketType)
				}
			}
		}
	}
}

impl Encode for Packet<'_> {
	fn encode(self, bytes: &mut BytesMut) {
		bytes.put_u8(self.packet_type.as_u8());
		bytes.put_u32_le(self.stream_id);
		self.packet_type.encode(bytes);
	}
}

impl<'a> TryFrom<Payload<'a>> for Packet<'a> {
	type Error = WispError;
	fn try_from(mut bytes: Payload<'a>) -> Result<Self, Self::Error> {
		if bytes.remaining() < 1 {
			return Err(Self::Error::PacketTooSmall);
		}
		let packet_type = bytes.get_u8();
		Self::parse_packet(packet_type, bytes)
	}
}

impl From<Packet<'_>> for BytesMut {
	fn from(packet: Packet) -> Self {
		let mut encoded = BytesMut::with_capacity(1 + 4 + packet.packet_type.get_packet_size());
		packet.encode(&mut encoded);
		encoded
	}
}

impl<'a> TryFrom<ws::Frame<'a>> for Packet<'a> {
	type Error = WispError;
	fn try_from(frame: ws::Frame<'a>) -> Result<Self, Self::Error> {
		if !frame.finished {
			return Err(Self::Error::WsFrameNotFinished);
		}
		if frame.opcode != ws::OpCode::Binary {
			return Err(Self::Error::WsFrameInvalidType);
		}
		Packet::try_from(frame.payload)
	}
}

impl From<Packet<'_>> for ws::Frame<'static> {
	fn from(packet: Packet) -> Self {
		Self::binary(Payload::Bytes(BytesMut::from(packet)))
	}
}
