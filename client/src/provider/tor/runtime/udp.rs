use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tor_rtcompat::{UdpProvider, UdpSocket};

use super::WasmTorRuntime;

/// Uninhabited `UdpSocket` placeholder. We never construct one.
pub enum WasmUdpSocket {}

#[async_trait]
impl UdpSocket for WasmUdpSocket {
	async fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
		match *self {}
	}

	async fn send(&self, _buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
		match *self {}
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		match *self {}
	}
}

#[async_trait]
impl UdpProvider for WasmTorRuntime {
	type UdpSocket = WasmUdpSocket;

	async fn bind(&self, _addr: &SocketAddr) -> io::Result<Self::UdpSocket> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"WasmTorRuntime does not support UDP",
		))
	}
}
