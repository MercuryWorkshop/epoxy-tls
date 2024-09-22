use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::FromStr,
};

use anyhow::Context;
use bytes::BytesMut;
use cfg_if::cfg_if;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use regex::RegexSet;
use tokio::net::{TcpStream, UdpSocket};
use wisp_mux::{ConnectPacket, StreamType};

use crate::{CONFIG, RESOLVER};

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
	#[cfg(feature = "twisp")]
	Pty(tokio::process::Child, pty_process::Pty),
	Blocked,
	Invalid,
}

pub enum ResolvedPacket {
	Valid(ConnectPacket),
	NoResolvedAddrs,
	Blocked,
	Invalid,
}

impl ClientStream {
	pub async fn resolve(packet: ConnectPacket) -> anyhow::Result<ResolvedPacket> {
		cfg_if! {
			if #[cfg(feature = "twisp")] {
				if let StreamType::Unknown(ty) = packet.stream_type {
					if ty == crate::handle::wisp::twisp::STREAM_TYPE && CONFIG.stream.allow_twisp && CONFIG.wisp.wisp_v2 {
						return Ok(ResolvedPacket::Valid(packet));
					} else {
						return Ok(ResolvedPacket::Invalid);
					}
				}
			} else {
				if matches!(packet.stream_type, StreamType::Unknown(_)) {
					return Ok(ResolvedPacket::Invalid);
				}
			}
		}

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

		let packet = RESOLVER
			.resolve(packet.destination_hostname)
			.await
			.context("failed to resolve hostname")?
			.filter(|x| CONFIG.server.resolve_ipv6 || x.is_ipv4())
			.map(|x| ConnectPacket {
				stream_type: packet.stream_type,
				destination_hostname: x.to_string(),
				destination_port: packet.destination_port,
			})
			.next();

		Ok(packet
			.map(ResolvedPacket::Valid)
			.unwrap_or(ResolvedPacket::NoResolvedAddrs))
	}

	pub async fn connect(packet: ConnectPacket) -> anyhow::Result<Self> {
		match packet.stream_type {
			StreamType::Tcp => {
				let ipaddr = IpAddr::from_str(&packet.destination_hostname)
					.context("failed to parse hostname as ipaddr")?;
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

				let ipaddr = IpAddr::from_str(&packet.destination_hostname)
					.context("failed to parse hostname as ipaddr")?;

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
			#[cfg(feature = "twisp")]
			StreamType::Unknown(crate::handle::wisp::twisp::STREAM_TYPE) => {
				if !CONFIG.stream.allow_twisp {
					return Ok(ClientStream::Blocked);
				}

				let cmdline: Vec<std::ffi::OsString> =
					shell_words::split(&packet.destination_hostname)?
						.into_iter()
						.map(Into::into)
						.collect();
				let pty = pty_process::Pty::new()?;

				let cmd = pty_process::Command::new(&cmdline[0])
					.args(&cmdline[1..])
					.spawn(&pty.pts()?)?;

				Ok(ClientStream::Pty(cmd, pty))
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
