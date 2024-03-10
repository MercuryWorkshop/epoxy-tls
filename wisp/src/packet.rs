use crate::{ws, WispError};
use bytes::{Buf, BufMut, Bytes};

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
        use CloseReason::*;
        match stream_type {
            0x01 => Ok(Unknown),
            0x02 => Ok(Voluntary),
            0x03 => Ok(Unexpected),
            0x41 => Ok(ServerStreamInvalidInfo),
            0x42 => Ok(ServerStreamUnreachable),
            0x43 => Ok(ServerStreamConnectionTimedOut),
            0x44 => Ok(ServerStreamConnectionRefused),
            0x47 => Ok(ServerStreamTimedOut),
            0x48 => Ok(ServerStreamBlockedAddress),
            0x49 => Ok(ServerStreamThrottled),
            0x81 => Ok(ClientUnexpected),
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

impl From<ConnectPacket> for Vec<u8> {
    fn from(packet: ConnectPacket) -> Self {
        let mut encoded = Self::with_capacity(1 + 2 + packet.destination_hostname.len());
        encoded.put_u8(packet.stream_type as u8);
        encoded.put_u16_le(packet.destination_port);
        encoded.extend(packet.destination_hostname.bytes());
        encoded
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

impl From<ContinuePacket> for Vec<u8> {
    fn from(packet: ContinuePacket) -> Self {
        let mut encoded = Self::with_capacity(4);
        encoded.put_u32_le(packet.buffer_remaining);
        encoded
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

impl From<ClosePacket> for Vec<u8> {
    fn from(packet: ClosePacket) -> Self {
        let mut encoded = Self::with_capacity(1);
        encoded.put_u8(packet.reason as u8);
        encoded
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
        }
    }
}

impl From<PacketType> for Vec<u8> {
    fn from(packet: PacketType) -> Self {
        use PacketType::*;
        match packet {
            Connect(x) => x.into(),
            Data(x) => x.to_vec(),
            Continue(x) => x.into(),
            Close(x) => x.into(),
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
        Self { stream_id, packet_type: packet }
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
}

impl TryFrom<Bytes> for Packet {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 5 {
            return Err(Self::Error::PacketTooSmall);
        }
        let packet_type = bytes.get_u8();
        use PacketType::*;
        Ok(Self {
            stream_id: bytes.get_u32_le(),
            packet_type: match packet_type {
                0x01 => Connect(ConnectPacket::try_from(bytes)?),
                0x02 => Data(bytes),
                0x03 => Continue(ContinuePacket::try_from(bytes)?),
                0x04 => Close(ClosePacket::try_from(bytes)?),
                _ => return Err(Self::Error::InvalidPacketType),
            },
        })
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Self {
        let mut encoded = Self::with_capacity(1 + 4);
        encoded.push(packet.packet_type.as_u8());
        encoded.put_u32_le(packet.stream_id);
        encoded.extend(Vec::<u8>::from(packet.packet_type));
        encoded
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
        Self::binary(Vec::<u8>::from(packet).into())
    }
}
