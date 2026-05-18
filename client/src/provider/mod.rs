use std::{
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, future::Either};
use futures_rustls::{
	TlsConnector,
	client::TlsStream,
	rustls::{ClientConfig, RootCertStore},
};
use hyper::Uri;
use pin_project::pin_project;
use service::{BoxProviderService, ProviderService};
use tower::Service;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{EpoxyError, EpoxyErrorExt, provider::extra_roots::EXTRA_TLS_SERVER_ROOTS};

mod extra_roots;
pub mod js;
pub mod service;
#[cfg(feature = "tor")]
pub mod tor;
pub mod wisp;

#[derive(Clone)]
pub struct ProviderServiceReq {
	pub host: String,
	pub port: u16,
}

#[derive(Clone, Copy)]
pub enum TlsAlpnMode {
	None,
	HttpAuto,
	Http1Only,
}

#[derive(Clone, Copy)]
pub enum HttpVersionMode {
	Auto,
	Http1Only,
}

#[pin_project]
pub struct ProviderEncryptedStream {
	#[pin]
	pub stream: TlsStream<ProviderUnencryptedStream>,
	#[cfg(feature = "full")]
	h2_negotiated: bool,
}
impl AsyncRead for ProviderEncryptedStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().stream.poll_read(cx, buf)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project().stream.poll_read_vectored(cx, bufs)
	}
}
impl AsyncWrite for ProviderEncryptedStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().stream.poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project().stream.poll_write_vectored(cx, bufs)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().stream.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().stream.poll_close(cx)
	}
}

pub struct ProviderUnencryptedStream {
	pub read: Box<dyn AsyncRead + Send + Unpin>,
	pub write: Box<dyn AsyncWrite + Send + Unpin>,
}
impl AsyncRead for ProviderUnencryptedStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.read).poll_read(cx, buf)
	}

	fn poll_read_vectored(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.read).poll_read_vectored(cx, bufs)
	}
}
impl AsyncWrite for ProviderUnencryptedStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.write).poll_write(cx, buf)
	}

	fn poll_write_vectored(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.write).poll_write_vectored(cx, bufs)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.write).poll_close(cx)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.write).poll_flush(cx)
	}
}
pub type ProviderStream = Either<ProviderUnencryptedStream, ProviderEncryptedStream>;

pub type StreamProviderBackendService =
	BoxProviderService<ProviderServiceReq, ProviderUnencryptedStream, EpoxyError>;

pub struct StreamProvider {
	service: StreamProviderBackendService,

	http_auto_config: Arc<ClientConfig>,
	http_h1_config: Arc<ClientConfig>,
	client_config: Arc<ClientConfig>,
}

impl StreamProvider {
	pub fn new(service: StreamProviderBackendService) -> Result<Self, EpoxyError> {
		let provider = Arc::new(futures_rustls::rustls::crypto::ring::default_provider());
		let client_config = ClientConfig::builder_with_provider(provider.clone())
			.with_safe_default_protocol_versions()?
			.with_root_certificates(
				TLS_SERVER_ROOTS
					.iter()
					.chain(EXTRA_TLS_SERVER_ROOTS.iter())
					.cloned()
					.collect::<RootCertStore>(),
			)
			.with_no_client_auth();
		let client_config = Arc::new(client_config);

		let http_auto_config = {
			let mut config = (*client_config).clone();
			config.alpn_protocols = vec!["http/1.1".as_bytes().to_vec()];

			#[cfg(feature = "full")]
			config.alpn_protocols.insert(0, "h2".as_bytes().to_vec());

			Arc::new(config)
		};

		let http_h1_config = {
			let mut config = (*client_config).clone();
			config.alpn_protocols = vec!["http/1.1".as_bytes().to_vec()];
			Arc::new(config)
		};

		Ok(Self {
			service,
			http_auto_config,
			http_h1_config,
			client_config,
		})
	}

	pub async fn get_stream(
		&self,
		host: String,
		port: u16,
	) -> Result<ProviderUnencryptedStream, EpoxyError> {
		self.service.call(ProviderServiceReq { host, port }).await
	}

	pub async fn get_tls_stream(
		&self,
		host: String,
		port: u16,
		alpn: TlsAlpnMode,
	) -> Result<ProviderEncryptedStream, EpoxyError> {
		let unencrypted = self.get_stream(host.clone(), port).await?;
		let connector = TlsConnector::from(
			match alpn {
				TlsAlpnMode::None => &self.client_config,
				TlsAlpnMode::HttpAuto => &self.http_auto_config,
				TlsAlpnMode::Http1Only => &self.http_h1_config,
			}
			.clone(),
		);

		let encrypted = connector
			.connect(
				host.clone().try_into().invalid_dns_name(host.clone())?,
				unencrypted,
			)
			.await?;

		#[cfg(feature = "full")]
		let h2_negotiated = encrypted
			.get_ref()
			.1
			.alpn_protocol()
			.is_some_and(|x| x == "h2".as_bytes());

		Ok(ProviderEncryptedStream {
			#[cfg(feature = "full")]
			h2_negotiated,
			stream: encrypted,
		})
	}
}

#[pin_project]
pub struct HttpIo {
	#[pin]
	inner: ProviderStream,
}

impl hyper::rt::Read for HttpIo {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		mut buf: hyper::rt::ReadBufCursor<'_>,
	) -> Poll<Result<(), std::io::Error>> {
		let buf_slice: &mut [u8] = unsafe {
			&mut *(std::ptr::from_mut::<[std::mem::MaybeUninit<u8>]>(buf.as_mut()) as *mut [u8])
		};
		match self.project().inner.poll_read(cx, buf_slice) {
			Poll::Ready(bytes_read) => {
				let bytes_read = bytes_read?;
				unsafe {
					buf.advance(bytes_read);
				}
				Poll::Ready(Ok(()))
			}
			Poll::Pending => Poll::Pending,
		}
	}
}

impl hyper::rt::Write for HttpIo {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, std::io::Error>> {
		self.project().inner.poll_write(cx, buf)
	}

	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Result<(), std::io::Error>> {
		self.project().inner.poll_flush(cx)
	}

	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Result<(), std::io::Error>> {
		self.project().inner.poll_close(cx)
	}

	fn poll_write_vectored(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<Result<usize, std::io::Error>> {
		self.project().inner.poll_write_vectored(cx, bufs)
	}
}

impl HttpIo {
	#[cfg(feature = "full")]
	pub fn is_negotiated_h2(&self) -> bool {
		matches!(&self.inner, Either::Right(tls_stream) if tls_stream.h2_negotiated)
	}
}

#[derive(Clone)]
pub struct StreamProviderService(pub Arc<StreamProvider>, pub HttpVersionMode);

impl StreamProviderService {
	pub fn auto(provider: Arc<StreamProvider>) -> Self {
		Self(provider, HttpVersionMode::Auto)
	}

	pub fn h1_only(provider: Arc<StreamProvider>) -> Self {
		Self(provider, HttpVersionMode::Http1Only)
	}
}

impl Service<Uri> for StreamProviderService {
	type Response = HttpIo;
	type Error = EpoxyError;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, req: Uri) -> Self::Future {
		let this = self.0.clone();
		let mode = self.1;

		Box::pin(async move {
			let scheme = req.scheme_str().ok_or(EpoxyError::InvalidUrlScheme(None))?;
			let host = req.host().ok_or(EpoxyError::NoUrlHost)?.to_string();
			let port = req.port_u16().map_or_else(
				|| match scheme {
					"https" | "wss" => Ok(443),
					"http" | "ws" => Ok(80),
					_ => Err(EpoxyError::NoUrlPort),
				},
				Ok,
			)?;

			Ok(HttpIo {
				inner: match scheme {
					"http" | "ws" => Either::Left(this.get_stream(host, port).await?),
					"https" => {
						let alpn = match mode {
							HttpVersionMode::Auto => TlsAlpnMode::HttpAuto,
							HttpVersionMode::Http1Only => TlsAlpnMode::Http1Only,
						};
						Either::Right(this.get_tls_stream(host, port, alpn).await?)
					}
					"wss" => {
						Either::Right(this.get_tls_stream(host, port, TlsAlpnMode::None).await?)
					}
					_ => return Err(EpoxyError::InvalidUrlScheme(Some(scheme.to_string()))),
				},
			})
		})
	}
}
