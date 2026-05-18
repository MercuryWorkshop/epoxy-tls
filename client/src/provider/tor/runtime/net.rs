use std::{
	io,
	net::SocketAddr,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, stream};
use pin_project::pin_project;
use tor_general_addr::unix;
use tor_rtcompat::{
	NetStreamListener, NetStreamProvider, StreamOps,
	unimpl::{FakeListener, FakeStream},
};

use crate::provider::{
	ProviderServiceReq, ProviderUnencryptedStream, StreamProviderBackendService,
	service::ProviderService,
};

use super::WasmTorRuntime;

/// A wrapper that wraps the JS-backed [`ProviderUnencryptedStream`] with the
/// extra trait bounds that `tor_rtcompat::NetStreamProvider` requires.
#[pin_project]
pub struct WasmTcpStream {
	#[pin]
	inner: ProviderUnencryptedStream,
}

// SAFETY: wasm32-unknown-unknown is single-threaded, so the JS handles inside
// `ProviderUnencryptedStream` are never actually shared across threads. We
// claim Sync only to satisfy `NetStreamProvider`'s trait bounds.
unsafe impl Sync for WasmTcpStream {}

impl AsyncRead for WasmTcpStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_read(cx, buf)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [io::IoSliceMut<'_>],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_read_vectored(cx, bufs)
	}
}

impl AsyncWrite for WasmTcpStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_write_vectored(cx, bufs)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().inner.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().inner.poll_close(cx)
	}
}

impl StreamOps for WasmTcpStream {}

/// Listener type used by [`NetStreamProvider<SocketAddr>`]. We never actually
/// build one (all `listen` calls return an error), but we need a type whose
/// `Stream` matches our [`WasmTcpStream`].
pub enum WasmTcpListener {}

impl NetStreamListener<SocketAddr> for WasmTcpListener {
	type Stream = WasmTcpStream;
	type Incoming = stream::Empty<io::Result<(WasmTcpStream, SocketAddr)>>;

	fn incoming(self) -> Self::Incoming {
		match self {}
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		match *self {}
	}
}

#[async_trait]
impl NetStreamProvider<SocketAddr> for WasmTorRuntime {
	type Stream = WasmTcpStream;
	type Listener = WasmTcpListener;

	async fn connect(&self, addr: &SocketAddr) -> io::Result<Self::Stream> {
		let svc: Arc<StreamProviderBackendService> = self.socket_provider();
		let host = addr.ip().to_string();
		let port = addr.port();

		let inner = svc
			.call(ProviderServiceReq { host, port })
			.await
			.map_err(io::Error::other)?;

		Ok(WasmTcpStream { inner })
	}

	async fn listen(&self, _addr: &SocketAddr) -> io::Result<Self::Listener> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"WasmTorRuntime cannot listen on TCP",
		))
	}
}

#[async_trait]
impl NetStreamProvider<unix::SocketAddr> for WasmTorRuntime {
	type Stream = FakeStream;
	type Listener = FakeListener<unix::SocketAddr>;

	async fn connect(&self, _addr: &unix::SocketAddr) -> io::Result<Self::Stream> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"WasmTorRuntime does not support AF_UNIX sockets",
		))
	}

	async fn listen(&self, _addr: &unix::SocketAddr) -> io::Result<Self::Listener> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"WasmTorRuntime does not support AF_UNIX sockets",
		))
	}
}

// `FakeListener` is uninhabited and trivially satisfies all `NetStreamListener`
// methods; nothing more to do here.
#[allow(dead_code)]
fn _assert_listener_trait() {
	fn assert<L: NetStreamListener<unix::SocketAddr>>() {}
	assert::<FakeListener<unix::SocketAddr>>();
}
