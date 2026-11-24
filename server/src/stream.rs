use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::FromStr,
};

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::BytesMut;
use cfg_if::cfg_if;
use fast_socks5::{
	client::{Socks5Datagram, Socks5Stream},
	util::target_addr::TargetAddr,
};
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::debug;
use regex::RegexSet;
use tokio::net::{TcpStream, UdpSocket};
use tokio_websockets::{CloseCode, Message, Payload, WebSocketStream};
use wisp_mux::{
	packet::{ConnectPacket, StreamType},
	stream::MuxStream,
};

use crate::{CONFIG, RESOLVER};

fn match_addr(str: &str, allowed: &RegexSet, blocked: &RegexSet) -> bool {
	blocked.is_match(str) && !allowed.is_match(str)
}

fn allowed_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.allowed_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.allowed_udp_hosts(),
		StreamType::Other(_) => unreachable!(),
	}
}

fn blocked_set(stream_type: StreamType) -> &'static RegexSet {
	match stream_type {
		StreamType::Tcp => CONFIG.stream.blocked_tcp_hosts(),
		StreamType::Udp => CONFIG.stream.blocked_udp_hosts(),
		StreamType::Other(_) => unreachable!(),
	}
}

pub enum ClientStream {
	Tcp(TcpStream),
	Udp(UdpSocket),
	UdpSocks5(Socks5Datagram<TcpStream>, TargetAddr),
	#[cfg(feature = "twisp")]
	Pty(tokio::process::Child, pty_process::Pty),
	Wispnet(MuxStream, String),

	NoResolvedAddrs,
	Blocked,
	Invalid,
}

// taken from rust 1.82.0
fn ipv4_is_global(addr: Ipv4Addr) -> bool {
	!(addr.octets()[0] == 0 // "This network"
            || addr.is_private()
            || (addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)) // || addr.is_shared()
            || addr.is_loopback()
            || addr.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // .9 and .10 are documented as globally reachable so they're excluded
            || (
                addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0
                && addr.octets()[3] != 9 && addr.octets()[3] != 10
            )
            || addr.is_documentation()
            || (addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18) // || addr.is_benchmarking()
            || (addr.octets()[0] & 240 == 240) // || addr.is_reserved()
            || addr.is_broadcast())
}
fn ipv6_is_global(addr: Ipv6Addr) -> bool {
	!(
		addr.is_unspecified()
            || addr.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(addr.segments(), [0x2002, _, _, _, _, _, _, _])
            || ((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)) // || addr.is_documentation()
            || (addr.segments()[0] & 0xfe00) == 0xfc00 // addr.is_unique_local()
            || (addr.segments()[0] & 0xfe00) == 0xfc00
		// || addr.is_unicast_link_local()
	)
}
fn is_global(addr: IpAddr) -> bool {
	match addr {
		IpAddr::V4(x) => ipv4_is_global(x),
		IpAddr::V6(x) => ipv6_is_global(x),
	}
}

pub enum ResolvedPacket {
	Valid(ConnectPacket),
	ValidWispnet(u32, ConnectPacket),
	NoResolvedAddrs,
	Blocked,
	Invalid,
}

impl ClientStream {
	pub async fn resolve(packet: ConnectPacket) -> anyhow::Result<ResolvedPacket> {
		if CONFIG.wisp.has_wispnet() && packet.host.ends_with(".wisp") {
			if let Some(wispnet_server) = packet.host.split(".wisp").next() {
				debug!("routing {:?} through wispnet", packet);
				let decoded = BASE64_STANDARD
					.decode(wispnet_server)
					.context("failed to decode wispnet server")?;
				let server_id = u32::from_str(
					&String::from_utf8(decoded).context("wispnet server was not a string")?,
				)
				.context("failed to parse wispnet server from string")?;
				return Ok(ResolvedPacket::ValidWispnet(server_id, packet));
			}
		}

		cfg_if! {
			if #[cfg(feature = "twisp")] {
				if let StreamType::Other(ty) = packet.stream_type {
					if ty == crate::handle::wisp::twisp::STREAM_TYPE && CONFIG.stream.allow_twisp && CONFIG.wisp.wisp_v2 {
						return Ok(ResolvedPacket::Valid(packet));
					}
					return Ok(ResolvedPacket::Invalid);
				}
			} else {
				if matches!(packet.stream_type, StreamType::Other(_)) {
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
			.any(|x| x.contains(&packet.port))
			&& !CONFIG
				.stream
				.allowed_ports()
				.iter()
				.any(|x| x.contains(&packet.port))
		{
			return Ok(ResolvedPacket::Blocked);
		}

		if let Ok(addr) = IpAddr::from_str(&packet.host) {
			if !CONFIG.stream.allow_direct_ip {
				return Ok(ResolvedPacket::Blocked);
			}

			if addr.is_loopback() && !CONFIG.stream.allow_loopback {
				return Ok(ResolvedPacket::Blocked);
			}

			if addr.is_multicast() && !CONFIG.stream.allow_multicast {
				return Ok(ResolvedPacket::Blocked);
			}

			if (is_global(addr) && !CONFIG.stream.allow_global)
				|| (!is_global(addr) && !CONFIG.stream.allow_non_global)
			{
				return Ok(ResolvedPacket::Blocked);
			}
		}

		if match_addr(
			&packet.host,
			allowed_set(packet.stream_type),
			blocked_set(packet.stream_type),
		) {
			return Ok(ResolvedPacket::Blocked);
		}

		// allow stream type whitelists through
		if match_addr(
			&packet.host,
			CONFIG.stream.allowed_hosts(),
			CONFIG.stream.blocked_hosts(),
		) && !allowed_set(packet.stream_type).is_match(&packet.host)
		{
			return Ok(ResolvedPacket::Blocked);
		}

		let packet = RESOLVER
			.resolve(packet.host)
			.await
			.context("failed to resolve hostname")?
			.filter(|x| CONFIG.server.resolve_ipv6 || x.is_ipv4())
			.map(|x| ConnectPacket {
				stream_type: packet.stream_type,
				host: x.to_string(),
				port: packet.port,
			})
			.next();

		Ok(packet.map_or(ResolvedPacket::NoResolvedAddrs, ResolvedPacket::Valid))
	}

	pub async fn connect(packet: ConnectPacket) -> anyhow::Result<Self> {
		match packet.stream_type {
			StreamType::Tcp => {
				let ipaddr =
					IpAddr::from_str(&packet.host).context("failed to parse hostname as ipaddr")?;

				let stream = if let Some(socks5_server) = CONFIG.stream.socks5_server() {
					Socks5Stream::connect(
						socks5_server,
						ipaddr.to_string(),
						packet.port,
						Default::default(),
					)
					.await
					.with_context(|| {
						format!(
							"failed to connect to host {} over socks5 {}",
							packet.host, socks5_server
						)
					})?
					.get_socket()
				} else {
					TcpStream::connect(SocketAddr::new(ipaddr, packet.port))
						.await
						.with_context(|| format!("failed to connect to host {}", packet.host))?
				};

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

				let ipaddr =
					IpAddr::from_str(&packet.host).context("failed to parse hostname as ipaddr")?;

				if let Some(socks5_server) = CONFIG.stream.socks5_server() {
					let bind_addr = if socks5_server.is_ipv4() {
						SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
					} else {
						SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
					};
					let backing = TcpStream::connect(socks5_server).await.with_context(|| {
						format!("failed to connect to socks5 {}", socks5_server)
					})?;
					let dgram = Socks5Datagram::bind(backing, bind_addr)
						.await
						.with_context(|| {
							format!(
								"failed to connect to host {} over socks5 {}",
								packet.host, socks5_server
							)
						})?;

					Ok(ClientStream::UdpSocks5(
						dgram,
						TargetAddr::Ip(SocketAddr::new(ipaddr, packet.port)),
					))
				} else {
					let bind_addr = if ipaddr.is_ipv4() {
						SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
					} else {
						SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
					};

					let stream = UdpSocket::bind(bind_addr).await?;

					stream
						.connect(SocketAddr::new(ipaddr, packet.port))
						.await
						.with_context(|| format!("failed to connect to host {}", packet.host))?;

					Ok(ClientStream::Udp(stream))
				}
			}
			#[cfg(feature = "twisp")]
			StreamType::Other(crate::handle::wisp::twisp::STREAM_TYPE) => {
				if !CONFIG.stream.allow_twisp {
					return Ok(ClientStream::Blocked);
				}

				let cmdline: Vec<std::ffi::OsString> = shell_words::split(&packet.host)?
					.into_iter()
					.map(Into::into)
					.collect();
				let pty = pty_process::Pty::new()?;

				let cmd = pty_process::Command::new(&cmdline[0])
					.args(&cmdline[1..])
					.spawn(&pty.pts()?)?;

				Ok(ClientStream::Pty(cmd, pty))
			}
			StreamType::Other(_) => Ok(ClientStream::Invalid),
		}
	}
}

pub enum WebSocketFrame {
	Data(BytesMut),
	Close,
	Ignore,
}

pub struct WebSocketStreamWrapper(pub WebSocketStream<TokioIo<Upgraded>>);

impl WebSocketStreamWrapper {
	pub async fn read(&mut self) -> Option<Result<WebSocketFrame, tokio_websockets::Error>> {
		let frame = self.0.next().await?;
		match frame {
			Ok(frame) if frame.is_binary() || frame.is_text() => {
				Some(Ok(WebSocketFrame::Data(frame.into_payload().into())))
			}
			Ok(frame) if frame.is_close() => Some(Ok(WebSocketFrame::Close)),
			Ok(_) => Some(Ok(WebSocketFrame::Ignore)),
			Err(err) => Some(Err(err)),
		}
	}

	pub async fn write(&mut self, data: impl Into<Payload>) -> Result<(), tokio_websockets::Error> {
		self.0.send(Message::binary(data)).await
	}

	pub async fn close(
		&mut self,
		code: CloseCode,
		reason: &str,
	) -> Result<(), tokio_websockets::Error> {
		self.0.send(Message::close(Some(code), reason)).await?;
		self.0.close().await
	}
}
