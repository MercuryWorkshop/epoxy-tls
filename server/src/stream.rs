use std::{
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	str::FromStr,
};

use anyhow::Context;
use bytes::BytesMut;
use futures_util::AsyncBufReadExt;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{
		lookup_host,
		tcp::{self, OwnedReadHalf, OwnedWriteHalf},
		unix, TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream,
	},
};
use tokio_util::either::Either;
use wisp_mux::{ConnectPacket, MuxStreamAsyncRead, MuxStreamWrite, StreamType};

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
				Self::Unix(UnixListener::bind(&CONFIG.server.bind).with_context(|| {
					format!("failed to bind to unix socket at `{}`", CONFIG.server.bind)
				})?)
			}
		})
	}

	pub async fn accept(&self) -> anyhow::Result<(ServerStream, Option<String>)> {
		match self {
			Self::Tcp(x) => x
				.accept()
				.await
				.map(|(x, y)| (Either::Left(x), Some(y.to_string())))
				.context("failed to accept tcp connection"),
			Self::Unix(x) => x
				.accept()
				.await
				.map(|(x, y)| {
					(
						Either::Right(x),
						y.as_pathname()
							.and_then(|x| x.to_str())
							.map(ToString::to_string),
					)
				})
				.context("failed to accept unix socket connection"),
		}
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

		if CONFIG
			.stream
			.blocked_hosts()
			.is_match(&packet.destination_hostname)
			&& !CONFIG
				.stream
				.allowed_hosts()
				.is_match(&packet.destination_hostname)
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

pub async fn copy_read_fast(
	mut muxrx: MuxStreamAsyncRead,
	mut tcptx: OwnedWriteHalf,
) -> std::io::Result<()> {
	loop {
		let buf = muxrx.fill_buf().await?;
		if buf.is_empty() {
			tcptx.flush().await?;
			return Ok(());
		}

		let i = tcptx.write(buf).await?;
		if i == 0 {
			return Err(std::io::ErrorKind::WriteZero.into());
		}

		muxrx.consume_unpin(i);
	}
}

#[allow(dead_code)]
pub async fn copy_write_fast(
	muxtx: MuxStreamWrite,
	mut tcprx: OwnedReadHalf,
) -> anyhow::Result<()> {
	loop {
		let mut buf = BytesMut::with_capacity(8 * 1024);
		let amt = tcprx.read(&mut buf).await?;
		muxtx.write(&buf[..amt]).await?;
	}
}
