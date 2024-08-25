use std::{io::ErrorKind, pin::Pin, sync::Arc, task::Poll};

use futures_rustls::{
	rustls::{ClientConfig, RootCertStore},
	TlsConnector,
};
use futures_util::{
	future::Either,
	lock::{Mutex, MutexGuard},
	AsyncRead, AsyncWrite, Future,
};
use hyper_util_wasm::client::legacy::connect::{ConnectSvc, Connected, Connection};
use lazy_static::lazy_static;
use pin_project_lite::pin_project;
use wasm_bindgen_futures::spawn_local;
use webpki_roots::TLS_SERVER_ROOTS;
use wisp_mux::{
	extensions::{udp::UdpProtocolExtensionBuilder, ProtocolExtensionBuilder},
	ws::{WebSocketRead, WebSocketWrite},
	ClientMux, MuxStreamAsyncRW, MuxStreamIo, StreamType,
};

use crate::{console_log, utils::IgnoreCloseNotify, EpoxyClientOptions, EpoxyError};

lazy_static! {
	static ref CLIENT_CONFIG: Arc<ClientConfig> = {
		let certstore = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
		Arc::new(
			ClientConfig::builder()
				.with_root_certificates(certstore)
				.with_no_client_auth(),
		)
	};
}

pub type ProviderUnencryptedStream = MuxStreamIo;
pub type ProviderUnencryptedAsyncRW = MuxStreamAsyncRW;
pub type ProviderTlsAsyncRW = IgnoreCloseNotify;
pub type ProviderAsyncRW = Either<ProviderTlsAsyncRW, ProviderUnencryptedAsyncRW>;
pub type ProviderWispTransportGenerator = Box<
	dyn Fn() -> Pin<
			Box<
				dyn Future<
						Output = Result<
							(
								Box<dyn WebSocketRead + Send>,
								Box<dyn WebSocketWrite + Send>,
							),
							EpoxyError,
						>,
					> + Sync
					+ Send,
			>,
		> + Sync
		+ Send,
>;

pub struct StreamProvider {
	wisp_generator: ProviderWispTransportGenerator,

	wisp_v2: bool,
	udp_extension: bool,

	current_client: Arc<Mutex<Option<ClientMux>>>,
}

impl StreamProvider {
	pub fn new(
		wisp_generator: ProviderWispTransportGenerator,
		options: &EpoxyClientOptions,
	) -> Result<Self, EpoxyError> {
		Ok(Self {
			wisp_generator,
			current_client: Arc::new(Mutex::new(None)),
			wisp_v2: options.wisp_v2,
			udp_extension: options.udp_extension_required,
		})
	}

	async fn create_client(
		&self,
		mut locked: MutexGuard<'_, Option<ClientMux>>,
	) -> Result<(), EpoxyError> {
		let extensions_vec: Vec<Box<dyn ProtocolExtensionBuilder + Send + Sync>> =
			vec![Box::new(UdpProtocolExtensionBuilder)];
		let extensions = if self.wisp_v2 {
			Some(extensions_vec.as_slice())
		} else {
			None
		};

		let (read, write) = (self.wisp_generator)().await?;

		let client = ClientMux::create(read, write, extensions).await?;
		let (mux, fut) = if self.udp_extension {
			client.with_udp_extension_required().await?
		} else {
			client.with_no_required_extensions()
		};
		locked.replace(mux);
		let current_client = self.current_client.clone();
		spawn_local(async move {
			console_log!("multiplexor future result: {:?}", fut.await);
			current_client.lock().await.take();
		});
		Ok(())
	}

	pub async fn replace_client(&self) -> Result<(), EpoxyError> {
		self.create_client(self.current_client.lock().await).await
	}

	pub async fn get_stream(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> Result<ProviderUnencryptedStream, EpoxyError> {
		Box::pin(async {
			let locked = self.current_client.lock().await;
			if let Some(mux) = locked.as_ref() {
				let stream = mux.client_new_stream(stream_type, host, port).await?;
				Ok(stream.into_io())
			} else {
				self.create_client(locked).await?;
				self.get_stream(stream_type, host, port).await
			}
		})
		.await
	}

	pub async fn get_asyncread(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> Result<ProviderUnencryptedAsyncRW, EpoxyError> {
		Ok(self
			.get_stream(stream_type, host, port)
			.await?
			.into_asyncrw())
	}

	pub async fn get_tls_stream(
		&self,
		host: String,
		port: u16,
	) -> Result<ProviderTlsAsyncRW, EpoxyError> {
		let stream = self
			.get_asyncread(StreamType::Tcp, host.clone(), port)
			.await?;
		let connector = TlsConnector::from(CLIENT_CONFIG.clone());
		let ret = connector
			.connect(host.try_into()?, stream)
			.into_fallible()
			.await;
		match ret {
			Ok(stream) => Ok(IgnoreCloseNotify {
				inner: stream.into(),
			}),
			Err((err, stream)) => {
				if matches!(err.kind(), ErrorKind::UnexpectedEof) {
					// maybe actually a wisp error?
					if let Some(reason) = stream.get_close_reason() {
						return Err(reason.into());
					}
				}
				Err(err.into())
			}
		}
	}
}

pin_project! {
	pub struct HyperIo {
		#[pin]
		inner: ProviderAsyncRW,
	}
}

impl hyper::rt::Read for HyperIo {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		mut buf: hyper::rt::ReadBufCursor<'_>,
	) -> Poll<Result<(), std::io::Error>> {
		let buf_slice: &mut [u8] = unsafe { std::mem::transmute(buf.as_mut()) };
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

impl hyper::rt::Write for HyperIo {
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

impl Connection for HyperIo {
	fn connected(&self) -> Connected {
		Connected::new()
	}
}

#[derive(Clone)]
pub struct StreamProviderService(pub Arc<StreamProvider>);

impl ConnectSvc for StreamProviderService {
	type Connection = HyperIo;
	type Error = EpoxyError;
	type Future = Pin<Box<impl Future<Output = Result<Self::Connection, Self::Error>>>>;

	fn connect(self, req: hyper::Uri) -> Self::Future {
		let provider = self.0.clone();
		Box::pin(async move {
			let scheme = req.scheme_str().ok_or(EpoxyError::InvalidUrlScheme)?;
			let host = req.host().ok_or(EpoxyError::NoUrlHost)?.to_string();
			let port = req.port_u16().map(Ok).unwrap_or_else(|| match scheme {
				"https" | "wss" => Ok(443),
				"http" | "ws" => Ok(80),
				_ => Err(EpoxyError::NoUrlPort),
			})?;
			Ok(HyperIo {
				inner: match scheme {
					"https" | "wss" => Either::Left(provider.get_tls_stream(host, port).await?),
					"http" | "ws" => {
						Either::Right(provider.get_asyncread(StreamType::Tcp, host, port).await?)
					}
					_ => return Err(EpoxyError::InvalidUrlScheme),
				},
			})
		})
	}
}
