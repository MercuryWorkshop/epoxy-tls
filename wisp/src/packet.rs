use std::fmt::Display;

use bytes::{Buf, BufMut};
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
	Role, WISP_VERSION, WispError,
	extensions::{AnyProtocolExtension, AnyProtocolExtensionBuilder},
	ws::{Payload, PayloadMut, PayloadRef},
};

trait PacketCodec: Sized {
	fn size_hint(&self) -> usize;

	fn encode_into(&self, packet: &mut PayloadMut);
	fn decode(packet: &mut Payload) -> Result<Self, WispError>;
}

#[derive(FromPrimitive, IntoPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamType {
	Tcp = 0x01,
	Udp = 0x02,
	#[num_enum(catch_all)]
	Other(u8),
}

impl PacketCodec for StreamType {
	fn size_hint(&self) -> usize {
		size_of::<u8>()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		packet.put_u8((*self).into());
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		if packet.remaining() < size_of::<u8>() {
			return Err(WispError::PacketTooSmall);
		}

		Ok(Self::from(packet.get_u8()))
	}
}

#[derive(FromPrimitive, IntoPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum CloseReason {
	/// Reason unspecified or unknown.
	Unknown = 0x01,
	/// Voluntary stream closure.
	Voluntary = 0x02,
	/// Unexpected stream closure due to a network error.
	Unexpected = 0x03,
	/// Incompatible extensions.
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

	/// The client has encountered an unexpected error and is unable to recieve any more data.
	ClientUnexpected = 0x81,

	/// Authentication failed due to invalid username/password.
	ExtensionsPasswordAuthFailed = 0xc0,
	/// Authentication failed due to invalid signature.
	ExtensionsCertAuthFailed = 0xc1,
	/// Authentication required but the client did not provide credentials.
	ExtensionsAuthRequired = 0xc2,

	#[num_enum(catch_all)]
	Other(u8),
}

impl Display for CloseReason {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use CloseReason as C;
		if let C::Other(x) = self {
			return write!(f, "Other: {x}");
		}

		write!(
			f,
			"{}",
			match self {
				C::Unknown => "Unknown close reason",
				C::Voluntary => "Voluntarily closed",
				C::Unexpected => "Unexpectedly closed",
				C::ExtensionsIncompatible => "Incompatible protocol extensions",

				C::ServerStreamInvalidInfo => "Stream creation failed due to invalid information",
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
				C::ExtensionsAuthRequired => "Authentication required",
				C::Other(_) => unreachable!(),
			}
		)
	}
}

impl PacketCodec for CloseReason {
	fn size_hint(&self) -> usize {
		size_of::<u8>()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		packet.put_u8((*self).into());
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		if packet.remaining() < size_of::<u8>() {
			return Err(WispError::PacketTooSmall);
		}

		Ok(Self::from(packet.get_u8()))
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConnectPacket {
	pub stream_type: StreamType,

	pub host: String,
	pub port: u16,
}

impl PacketCodec for ConnectPacket {
	fn size_hint(&self) -> usize {
		self.stream_type.size_hint() + self.host.len() + size_of::<u16>()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		self.stream_type.encode_into(packet);
		packet.put_u16_le(self.port);
		packet.extend_from_slice(self.host.as_bytes());
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		if packet.remaining() < (size_of::<u8>() + size_of::<u16>()) {
			return Err(WispError::PacketTooSmall);
		}

		let stream_type = StreamType::decode(packet)?;
		let port = packet.get_u16_le();
		let host = String::from_utf8(packet.to_vec())?;

		Ok(Self {
			stream_type,
			host,
			port,
		})
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ContinuePacket {
	pub buffer_remaining: u32,
}

impl PacketCodec for ContinuePacket {
	fn size_hint(&self) -> usize {
		size_of::<u32>()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		packet.put_u32_le(self.buffer_remaining);
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		if packet.remaining() < size_of::<u32>() {
			return Err(WispError::PacketTooSmall);
		}

		let buffer_remaining = packet.get_u32_le();

		Ok(Self { buffer_remaining })
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ClosePacket {
	pub reason: CloseReason,
}

impl PacketCodec for ClosePacket {
	fn size_hint(&self) -> usize {
		self.reason.size_hint()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		self.reason.encode_into(packet);
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		let reason = CloseReason::decode(packet)?;

		Ok(Self { reason })
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct WispVersion {
	pub major: u8,
	pub minor: u8,
}

impl Display for WispVersion {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}.{}", self.major, self.minor)
	}
}

impl PacketCodec for WispVersion {
	fn size_hint(&self) -> usize {
		size_of::<u8>() * 2
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		packet.put_u8(self.major);
		packet.put_u8(self.minor);
	}

	fn decode(packet: &mut Payload) -> Result<Self, WispError> {
		if packet.remaining() < 2 {
			return Err(WispError::PacketTooSmall);
		}

		Ok(Self {
			major: packet.get_u8(),
			minor: packet.get_u8(),
		})
	}
}

#[derive(Debug, Clone)]
pub struct InfoPacket {
	pub version: WispVersion,
	pub extensions: Vec<AnyProtocolExtension>,
}

impl InfoPacket {
	pub(crate) fn decode(
		packet: &mut Payload,
		builders: &mut [AnyProtocolExtensionBuilder],
		role: Role,
	) -> Result<Self, WispError> {
		if packet.remaining() < (size_of::<u8>() * 2) {
			return Err(WispError::PacketTooSmall);
		}

		let version = WispVersion {
			major: packet.get_u8(),
			minor: packet.get_u8(),
		};

		if version.major != WISP_VERSION.major {
			return Err(WispError::IncompatibleProtocolVersion(
				version,
				WISP_VERSION,
			));
		}

		let mut extensions = Vec::new();

		while packet.remaining() >= (size_of::<u8>() + size_of::<u32>()) {
			// We have some extensions
			let id = packet.get_u8();
			let length = usize::try_from(packet.get_u32_le())?;

			if packet.remaining() < length {
				return Err(WispError::PacketTooSmall);
			}

			if let Some(builder) = builders.iter_mut().find(|x| x.get_id() == id) {
				extensions.push(builder.build_from_bytes(packet.split_to(length), role)?);
			} else {
				packet.advance(length);
			}
		}

		Ok(Self {
			version,
			extensions,
		})
	}

	pub(crate) fn encode(&self) -> Payload {
		let mut packet = PayloadMut::with_capacity(
			size_of::<u8>() + size_of::<u32>() + self.version.size_hint(),
		);
		packet.put_u8(0x05);
		packet.put_u32(0);
		self.version.encode_into(&mut packet);
		for extension in &self.extensions {
			extension.encode_into(&mut packet);
		}
		packet.freeze()
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PacketType<'a> {
	Connect(ConnectPacket),
	Data(PayloadRef<'a>),
	Continue(ContinuePacket),
	Close(ClosePacket),
}

impl PacketType<'_> {
	pub(crate) fn size_hint(&self) -> usize {
		match self {
			Self::Connect(x) => x.size_hint(),
			Self::Data(x) => x.len(),
			Self::Continue(x) => x.size_hint(),
			Self::Close(x) => x.size_hint(),
		}
	}

	pub(crate) fn get_type(&self) -> u8 {
		match self {
			Self::Connect(_) => 0x01,
			Self::Data(_) => 0x02,
			Self::Continue(_) => 0x03,
			Self::Close(_) => 0x04,
		}
	}

	pub(crate) fn encode(&self, packet: &mut PayloadMut) {
		match self {
			Self::Connect(x) => x.encode_into(packet),
			Self::Data(x) => packet.extend_from_slice(x),
			Self::Continue(x) => x.encode_into(packet),
			Self::Close(x) => x.encode_into(packet),
		}
	}

	pub(crate) fn decode(mut packet: Payload, ty: u8) -> Result<PacketType<'static>, WispError> {
		Ok(match ty {
			0x01 => PacketType::Connect(ConnectPacket::decode(&mut packet)?),
			0x02 => PacketType::Data(packet.into()),
			0x03 => PacketType::Continue(ContinuePacket::decode(&mut packet)?),
			0x04 => PacketType::Close(ClosePacket::decode(&mut packet)?),
			x => return Err(WispError::InvalidPacketType(x)),
		})
	}
}

pub(crate) enum MaybeInfoPacket<'a> {
	Packet(Packet<'a>),
	Info(InfoPacket),
}

impl MaybeInfoPacket<'static> {
	pub(crate) fn decode(
		mut packet: Payload,
		builders: &mut [AnyProtocolExtensionBuilder],
		role: Role,
	) -> Result<Self, WispError> {
		if packet.remaining() < size_of::<u8>() + size_of::<u32>() {
			return Err(WispError::PacketTooSmall);
		}

		let ty = packet.get_u8();
		let stream_id = packet.get_u32_le();

		if ty == 0x05 {
			Ok(Self::Info(InfoPacket::decode(&mut packet, builders, role)?))
		} else {
			Ok(Self::Packet(Packet {
				stream_id,
				packet_type: PacketType::decode(packet, ty)?,
			}))
		}
	}
}

pub(crate) enum MaybeExtensionPacket<'a> {
	Packet(Packet<'a>),
	Extension(u8, u32, Payload),
}

impl MaybeExtensionPacket<'static> {
	pub(crate) fn decode(mut packet: Payload) -> Result<Self, WispError> {
		if packet.remaining() < size_of::<u8>() + size_of::<u32>() {
			return Err(WispError::PacketTooSmall);
		}

		let ty = packet.get_u8();
		let stream_id = packet.get_u32_le();

		if (0x01..=0x04).contains(&ty) {
			Ok(Self::Packet(Packet {
				stream_id,
				packet_type: PacketType::decode(packet, ty)?,
			}))
		} else {
			Ok(Self::Extension(ty, stream_id, packet))
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Packet<'a> {
	pub stream_id: u32,
	pub packet_type: PacketType<'a>,
}

impl Packet<'_> {
	fn size_hint(&self) -> usize {
		size_of::<u8>() + size_of::<u32>() + self.packet_type.size_hint()
	}

	fn encode_into(&self, packet: &mut PayloadMut) {
		packet.put_u8(self.packet_type.get_type());
		packet.put_u32_le(self.stream_id);
		self.packet_type.encode(packet);
	}

	pub(crate) fn encode(&self) -> Payload {
		let mut payload = PayloadMut::with_capacity(self.size_hint());
		self.encode_into(&mut payload);
		payload.into()
	}

	pub(crate) fn decode(mut packet: Payload) -> Result<Packet<'static>, WispError> {
		if packet.remaining() < size_of::<u8>() + size_of::<u32>() {
			return Err(WispError::PacketTooSmall);
		}

		let ty = packet.get_u8();
		let stream_id = packet.get_u32_le();

		Ok(Packet {
			stream_id,
			packet_type: PacketType::decode(packet, ty)?,
		})
	}

	pub fn new_data<'a>(stream_id: u32, data: impl Into<PayloadRef<'a>>) -> Packet<'a> {
		Packet {
			stream_id,
			packet_type: PacketType::Data(data.into()),
		}
	}

	pub fn new_continue(stream_id: u32, buffer_remaining: u32) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Continue(ContinuePacket { buffer_remaining }),
		}
	}

	pub fn new_close(stream_id: u32, reason: CloseReason) -> Self {
		Self {
			stream_id,
			packet_type: PacketType::Close(ClosePacket { reason }),
		}
	}
}
