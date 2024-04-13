use crate::{
    extensions::{AnyProtocolExtension, ProtocolExtensionBuilder},
    ws::{self, Frame, LockedWebSocketWrite, OpCode, WebSocketRead},
    Role, WispError, WISP_VERSION,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Wisp stream type.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum StreamType {
    /// TCP Wisp stream.
    Tcp = 0x01,
    /// UDP Wisp stream.
    Udp = 0x02,
}

impl TryFrom<u8> for StreamType {
    type Error = WispError;
    fn try_from(stream_type: u8) -> Result<Self, Self::Error> {
        use StreamType::*;
        match stream_type {
            0x01 => Ok(Tcp),
            0x02 => Ok(Udp),
            _ => Err(Self::Error::InvalidStreamType),
        }
    }
}

/// Close reason.
///
/// See [the
/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#clientserver-close-reasons)
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CloseReason {
    /// Reason unspecified or unknown.
    Unknown = 0x01,
    /// Voluntary stream closure.
    Voluntary = 0x02,
    /// Unexpected stream closure due to a network error.
    Unexpected = 0x03,
    /// Incompatible extensions. Only used during the handshake.
    IncompatibleExtensions = 0x04,
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
}

impl TryFrom<u8> for CloseReason {
    type Error = WispError;
    fn try_from(stream_type: u8) -> Result<Self, Self::Error> {
        use CloseReason as R;
        match stream_type {
            0x01 => Ok(R::Unknown),
            0x02 => Ok(R::Voluntary),
            0x03 => Ok(R::Unexpected),
            0x04 => Ok(R::IncompatibleExtensions),
            0x41 => Ok(R::ServerStreamInvalidInfo),
            0x42 => Ok(R::ServerStreamUnreachable),
            0x43 => Ok(R::ServerStreamConnectionTimedOut),
            0x44 => Ok(R::ServerStreamConnectionRefused),
            0x47 => Ok(R::ServerStreamTimedOut),
            0x48 => Ok(R::ServerStreamBlockedAddress),
            0x49 => Ok(R::ServerStreamThrottled),
            0x81 => Ok(R::ClientUnexpected),
            _ => Err(Self::Error::InvalidStreamType),
        }
    }
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

impl TryFrom<Bytes> for ConnectPacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < (1 + 2) {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            stream_type: bytes.get_u8().try_into()?,
            destination_port: bytes.get_u16_le(),
            destination_hostname: std::str::from_utf8(&bytes)?.to_string(),
        })
    }
}

impl From<ConnectPacket> for Bytes {
    fn from(packet: ConnectPacket) -> Self {
        let mut encoded = BytesMut::with_capacity(1 + 2 + packet.destination_hostname.len());
        encoded.put_u8(packet.stream_type as u8);
        encoded.put_u16_le(packet.destination_port);
        encoded.extend(packet.destination_hostname.bytes());
        encoded.freeze()
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

impl TryFrom<Bytes> for ContinuePacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 4 {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            buffer_remaining: bytes.get_u32_le(),
        })
    }
}

impl From<ContinuePacket> for Bytes {
    fn from(packet: ContinuePacket) -> Self {
        let mut encoded = BytesMut::with_capacity(4);
        encoded.put_u32_le(packet.buffer_remaining);
        encoded.freeze()
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

impl TryFrom<Bytes> for ClosePacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 1 {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            reason: bytes.get_u8().try_into()?,
        })
    }
}

impl From<ClosePacket> for Bytes {
    fn from(packet: ClosePacket) -> Self {
        let mut encoded = BytesMut::with_capacity(1);
        encoded.put_u8(packet.reason as u8);
        encoded.freeze()
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

impl From<InfoPacket> for Bytes {
    fn from(value: InfoPacket) -> Self {
        let mut bytes = BytesMut::with_capacity(2);
        bytes.put_u8(value.version.major);
        bytes.put_u8(value.version.minor);
        for extension in value.extensions {
            bytes.extend(Bytes::from(extension));
        }
        bytes.freeze()
    }
}

#[derive(Debug, Clone)]
/// Type of packet recieved.
pub enum PacketType {
    /// Connect packet.
    Connect(ConnectPacket),
    /// Data packet.
    Data(Bytes),
    /// Continue packet.
    Continue(ContinuePacket),
    /// Close packet.
    Close(ClosePacket),
    /// Info packet.
    Info(InfoPacket),
}

impl PacketType {
    /// Get the packet type used in the protocol.
    pub fn as_u8(&self) -> u8 {
        use PacketType::*;
        match self {
            Connect(_) => 0x01,
            Data(_) => 0x02,
            Continue(_) => 0x03,
            Close(_) => 0x04,
            Info(_) => 0x05,
        }
    }
}

impl From<PacketType> for Bytes {
    fn from(packet: PacketType) -> Self {
        use PacketType::*;
        match packet {
            Connect(x) => x.into(),
            Data(x) => x,
            Continue(x) => x.into(),
            Close(x) => x.into(),
            Info(x) => x.into(),
        }
    }
}

/// Wisp protocol packet.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Stream this packet is associated with.
    pub stream_id: u32,
    /// Packet type recieved.
    pub packet_type: PacketType,
}

impl Packet {
    /// Create a new packet.
    ///
    /// The helper functions should be used for most use cases.
    pub fn new(stream_id: u32, packet: PacketType) -> Self {
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
    pub fn new_data(stream_id: u32, data: Bytes) -> Self {
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

    fn parse_packet(packet_type: u8, mut bytes: Bytes) -> Result<Self, WispError> {
        use PacketType::*;
        Ok(Self {
            stream_id: bytes.get_u32_le(),
            packet_type: match packet_type {
                0x01 => Connect(ConnectPacket::try_from(bytes)?),
                0x02 => Data(bytes),
                0x03 => Continue(ContinuePacket::try_from(bytes)?),
                0x04 => Close(ClosePacket::try_from(bytes)?),
                // 0x05 is handled seperately
                _ => return Err(WispError::InvalidPacketType),
            },
        })
    }

    pub(crate) fn maybe_parse_info(
        frame: Frame,
        role: Role,
        extension_builders: &[&(dyn ProtocolExtensionBuilder + Sync)],
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
        frame: Frame,
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
        if bytes.remaining() < 1 {
            return Err(WispError::PacketTooSmall);
        }
        let packet_type = bytes.get_u8();
        if let Some(extension) = extensions
            .iter_mut()
            .find(|x| x.get_supported_packets().iter().any(|x| *x == packet_type))
        {
            extension.handle_packet(bytes, read, write).await?;
            Ok(None)
        } else {
            Ok(Some(Self::parse_packet(packet_type, bytes)?))
        }
    }

    fn parse_info(
        mut bytes: Bytes,
        role: Role,
        extension_builders: &[&(dyn ProtocolExtensionBuilder + Sync)],
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

        let mut extensions = Vec::new();

        while bytes.remaining() > 4 {
            // We have some extensions
            let id = bytes.get_u8();
            let length = usize::try_from(bytes.get_u32_le())?;
            if bytes.remaining() < length {
                return Err(WispError::PacketTooSmall);
            }
            if let Some(builder) = extension_builders.iter().find(|x| x.get_id() == id) {
                extensions.push(builder.build(bytes.copy_to_bytes(length), role))
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
}

impl TryFrom<Bytes> for Packet {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 5 {
            return Err(Self::Error::PacketTooSmall);
        }
        let packet_type = bytes.get_u8();
        Self::parse_packet(packet_type, bytes)
    }
}

impl From<Packet> for Bytes {
    fn from(packet: Packet) -> Self {
        let inner_u8 = packet.packet_type.as_u8();
        let inner = Bytes::from(packet.packet_type);
        let mut encoded = BytesMut::with_capacity(1 + 4 + inner.len());
        encoded.put_u8(inner_u8);
        encoded.put_u32_le(packet.stream_id);
        encoded.extend(inner);
        encoded.freeze()
    }
}

impl TryFrom<ws::Frame> for Packet {
    type Error = WispError;
    fn try_from(frame: ws::Frame) -> Result<Self, Self::Error> {
        if !frame.finished {
            return Err(Self::Error::WsFrameNotFinished);
        }
        if frame.opcode != ws::OpCode::Binary {
            return Err(Self::Error::WsFrameInvalidType);
        }
        frame.payload.try_into()
    }
}

impl From<Packet> for ws::Frame {
    fn from(packet: Packet) -> Self {
        Self::binary(packet.into())
    }
}
