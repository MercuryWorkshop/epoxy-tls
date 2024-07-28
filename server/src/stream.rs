use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::FromStr,
};

use anyhow::Context;
use bytes::BytesMut;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use regex::RegexSet;
use tokio::{
	fs::{remove_file, try_exists},
	net::{lookup_host, tcp, unix, TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
};
use tokio_util::either::Either;
use uuid::Uuid;
use wisp_mux::{ConnectPacket, StreamType};

use crate::{config::SocketType, CONFIG};

pub enum ServerListener {
	Tcp(TcpListener),
	Unix(UnixListener),
}

pub type ServerStream = Either<TcpStream, UnixStream>;
pub type ServerStreamRead = Either<tcp::OwnedReadHalf, unix::OwnedReadHalf>;
pub type ServerStreamWrite = Either<tcp::OwnedWriteHalf, unix::OwnedWriteHalf>;

pub trait ServerStreamExt {
	fn split(self) -> (ServerStreamRead, ServerStreamWrite);
}

impl ServerStreamExt for ServerStream {
	fn split(self) -> (ServerStreamRead, ServerStreamWrite) {
		match self {
			Self::Left(x) => {
				let (r, w) = x.into_split();
				(Either::Left(r), Either::Left(w))
			}
			Self::Right(x) => {
				let (r, w) = x.into_split();
				(Either::Right(r), Either::Right(w))
			}
		}
	}
}

impl ServerListener {
	pub async fn new() -> anyhow::Result<Self> {
		Ok(match CONFIG.server.socket {
			SocketType::Tcp => Self::Tcp(
				TcpListener::bind(&CONFIG.server.bind)
					.await
					.with_context(|| {
						format!("failed to bind to tcp address `{}`", CONFIG.server.bind)
					})?,
			),
			SocketType::Unix => {
				if try_exists(&CONFIG.server.bind).await? {
					remove_file(&CONFIG.server.bind).await?;
				}
				Self::Unix(UnixListener::bind(&CONFIG.server.bind).with_context(|| {
					format!("failed to bind to unix socket at `{}`", CONFIG.server.bind)
				})?)
			}
		})
	}

	pub async fn accept(&self) -> anyhow::Result<(ServerStream, String)> {
		match self {
			Self::Tcp(x) => {
				let (stream, addr) = x
					.accept()
					.await
					.context("failed to accept tcp connection")?;
				if CONFIG.server.tcp_nodelay {
					stream
						.set_nodelay(true)
						.context("failed to set tcp nodelay")?;
				}
				Ok((Either::Left(stream), addr.to_string()))
			}
			Self::Unix(x) => x
				.accept()
				.await
				.map(|(x, y)| {
					(
						Either::Right(x),
						y.as_pathname()
							.and_then(|x| x.to_str())
							.map(ToString::to_string)
							.unwrap_or_else(|| Uuid::new_v4().to_string() + "-unix_socket"),
					)
				})
				.context("failed to accept unix socket connection"),
		}
	}
}

fn match_addr(str: &str, allowed: &RegexSet, blocked: &RegexSet) -> bool {
	blocked.is_match(str) && !allowed.is_match(str)
}

fn allowed_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.allowed_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.allowed_udp_hosts(),
		StreamType::Unknown(_) => unreachable!(),
	}
}

fn blocked_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.blocked_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.blocked_udp_hosts(),
		StreamType::Unknown(_) => unreachable!(),
	}
}

pub enum ClientStream {
	Tcp(TcpStream),
	Udp(UdpSocket),
	Blocked,
	Invalid,
}

pub enum ResolvedPacket {
	Valid(ConnectPacket),
	NoResolvedAddrs,
	Blocked,
}

impl ClientStream {
	pub async fn resolve(packet: ConnectPacket) -> anyhow::Result<ResolvedPacket> {
		if !CONFIG.stream.allow_udp && packet.stream_type == StreamType::Udp {
			return Ok(ResolvedPacket::Blocked);
		}

		if CONFIG
			.stream
			.blocked_ports()
			.iter()
			.any(|x| x.contains(&packet.destination_port))
			&& !CONFIG
				.stream
				.allowed_ports()
				.iter()
				.any(|x| x.contains(&packet.destination_port))
		{
			return Ok(ResolvedPacket::Blocked);
		}

		if let Ok(addr) = IpAddr::from_str(&packet.destination_hostname) {
			if !CONFIG.stream.allow_direct_ip {
				return Ok(ResolvedPacket::Blocked);
			}

			if addr.is_loopback() && !CONFIG.stream.allow_loopback {
				return Ok(ResolvedPacket::Blocked);
			}

			if addr.is_multicast() && !CONFIG.stream.allow_multicast {
				return Ok(ResolvedPacket::Blocked);
			}

			if (addr.is_global() && !CONFIG.stream.allow_global)
				|| (!addr.is_global() && !CONFIG.stream.allow_non_global)
			{
				return Ok(ResolvedPacket::Blocked);
			}
		}

		if match_addr(
			&packet.destination_hostname,
			allowed_set(packet.stream_type),
			blocked_set(packet.stream_type),
		) {
			return Ok(ResolvedPacket::Blocked);
		}

		// allow stream type whitelists through
		if match_addr(
			&packet.destination_hostname,
			CONFIG.stream.allowed_hosts(),
			CONFIG.stream.blocked_hosts(),
		) && !allowed_set(packet.stream_type).is_match(&packet.destination_hostname)
		{
			return Ok(ResolvedPacket::Blocked);
		}

		let packet = lookup_host(packet.destination_hostname + ":0")
			.await
			.context("failed to resolve hostname")?
			.filter(|x| CONFIG.server.resolve_ipv6 || x.is_ipv4())
			.map(|x| ConnectPacket {
				stream_type: packet.stream_type,
				destination_hostname: x.ip().to_string(),
				destination_port: packet.destination_port,
			})
			.next();

		Ok(packet
			.map(ResolvedPacket::Valid)
			.unwrap_or(ResolvedPacket::NoResolvedAddrs))
	}

	pub async fn connect(packet: ConnectPacket) -> anyhow::Result<Self> {
		let ipaddr = IpAddr::from_str(&packet.destination_hostname)
			.context("failed to parse hostname as ipaddr")?;

		match packet.stream_type {
			StreamType::Tcp => {
				let stream = TcpStream::connect(SocketAddr::new(ipaddr, packet.destination_port))
					.await
					.with_context(|| {
						format!("failed to connect to host {}", packet.destination_hostname)
					})?;

				if CONFIG.stream.tcp_nodelay {
					stream
						.set_nodelay(true)
						.context("failed to set tcp nodelay")?;
				}

				Ok(ClientStream::Tcp(stream))
			}
			StreamType::Udp => {
				if !CONFIG.stream.allow_udp {
					return Ok(ClientStream::Blocked);
				}

				let bind_addr = if ipaddr.is_ipv4() {
					SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0)
				} else {
					SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0)
				};

				let stream = UdpSocket::bind(bind_addr).await?;

				stream
					.connect(SocketAddr::new(ipaddr, packet.destination_port))
					.await?;

				Ok(ClientStream::Udp(stream))
			}
			StreamType::Unknown(_) => Ok(ClientStream::Invalid),
		}
	}
}

pub enum WebSocketFrame {
	Data(BytesMut),
	Close,
	Ignore,
}

pub struct WebSocketStreamWrapper(pub FragmentCollector<TokioIo<Upgraded>>);

impl WebSocketStreamWrapper {
	pub async fn read(&mut self) -> Result<WebSocketFrame, WebSocketError> {
		let frame = self.0.read_frame().await?;
		Ok(match frame.opcode {
			OpCode::Text | OpCode::Binary => WebSocketFrame::Data(frame.payload.into()),
			OpCode::Close => WebSocketFrame::Close,
			_ => WebSocketFrame::Ignore,
		})
	}

	pub async fn write(&mut self, data: &[u8]) -> Result<(), WebSocketError> {
		self.0
			.write_frame(Frame::binary(Payload::Borrowed(data)))
			.await
	}

	pub async fn close(&mut self, code: u16, reason: &[u8]) -> Result<(), WebSocketError> {
		self.0.write_frame(Frame::close(code, reason)).await
	}
}
