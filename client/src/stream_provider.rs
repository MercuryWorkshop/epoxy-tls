use std::{io::ErrorKind, pin::Pin, sync::Arc, task::Poll};

use cfg_if::cfg_if;
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
use pin_project_lite::pin_project;
use send_wrapper::SendWrapper;
use wasm_bindgen_futures::spawn_local;
use webpki_roots::TLS_SERVER_ROOTS;
use wisp_mux::{
	extensions::{udp::UdpProtocolExtensionBuilder, AnyProtocolExtensionBuilder},
	packet::{CloseReason, StreamType},
	stream::{MuxStream, MuxStreamAsyncRW},
	ws::{TransportRead, TransportWrite},
	ClientMux, WispV2Handshake,
};

use crate::{
	console_error, console_log,
	utils::{IgnoreCloseNotify, NoCertificateVerification},
	EpoxyClientOptions, EpoxyError,
};

pub type ProviderUnencryptedStream = MuxStream<ProviderWispTransportWrite>;
pub type ProviderUnencryptedAsyncRW = MuxStreamAsyncRW<ProviderWispTransportWrite>;
pub type ProviderTlsAsyncRW = IgnoreCloseNotify;
pub type ProviderAsyncRW = Either<ProviderTlsAsyncRW, ProviderUnencryptedAsyncRW>;
pub type ProviderWispTransportRead = Pin<Box<dyn TransportRead>>;
pub type ProviderWispTransportWrite = Pin<Box<dyn TransportWrite>>;
pub type ProviderWispTransportGenerator = Box<
	dyn Fn(
			bool,
		) -> Pin<
			Box<
				dyn Future<
						Output = Result<
							(ProviderWispTransportRead, ProviderWispTransportWrite),
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

	current_client: Arc<Mutex<Option<ClientMux<ProviderWispTransportWrite>>>>,

	h2_config: Arc<ClientConfig>,
	client_config: Arc<ClientConfig>,
}

impl StreamProvider {
	pub fn new(
		wisp_generator: ProviderWispTransportGenerator,
		options: &EpoxyClientOptions,
	) -> Result<Self, EpoxyError> {
		let provider = Arc::new(futures_rustls::rustls::crypto::ring::default_provider());
		let client_config = ClientConfig::builder_with_provider(provider.clone())
			.with_safe_default_protocol_versions()?;
		let mut client_config = if options.disable_certificate_validation {
			client_config
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
		} else {
			cfg_if! {
				if #[cfg(feature = "full")] {
					let pems: Result<Result<Vec<_>, webpki::Error>, std::io::Error> = options
						.pem_files
						.iter()
						.flat_map(|x| {
							rustls_pemfile::certs(&mut std::io::BufReader::new(x.as_bytes()))
								.map(|x| x.map(|x| webpki::anchor_from_trusted_cert(&x).map(|x| x.to_owned())))
								.collect::<Vec<_>>()
						})
						.collect();
					let pems = pems.map_err(EpoxyError::Pemfile)??;
					let certstore: RootCertStore = pems.into_iter().chain(TLS_SERVER_ROOTS.iter().cloned()).collect();
				} else {
					let certstore: RootCertStore = TLS_SERVER_ROOTS.iter().cloned().collect();
				}
			}
			client_config.with_root_certificates(certstore)
		}
		.with_no_client_auth();
		let no_alpn_client_config = Arc::new(client_config.clone());
		#[cfg(feature = "full")]
		{
			client_config.alpn_protocols =
				vec!["h2".as_bytes().to_vec(), "http/1.1".as_bytes().to_vec()];
		}
		let client_config = Arc::new(client_config);

		Ok(Self {
			wisp_generator,
			current_client: Arc::new(Mutex::new(None)),
			wisp_v2: options.wisp_v2,
			udp_extension: options.udp_extension_required,
			h2_config: client_config,
			client_config: no_alpn_client_config,
		})
	}

	async fn create_client(
		&self,
		mut locked: MutexGuard<'_, Option<ClientMux<ProviderWispTransportWrite>>>,
	) -> Result<(), EpoxyError> {
		let extensions_vec: Vec<AnyProtocolExtensionBuilder> =
			vec![AnyProtocolExtensionBuilder::new(
				UdpProtocolExtensionBuilder,
			)];
		let extensions = if self.wisp_v2 {
			Some(WispV2Handshake::new(extensions_vec))
		} else {
			None
		};

		let (read, write) = (self.wisp_generator)(self.wisp_v2).await?;

		let client = ClientMux::new(read, write, extensions).await?;
		let (mux, fut) = if self.udp_extension {
			client.with_udp_extension_required().await?
		} else {
			client.with_no_required_extensions()
		};
		locked.replace(mux);
		let current_client = self.current_client.clone();
		spawn_local(async move {
			match fut.await {
				Ok(()) => console_log!("epoxy: wisp multiplexor task ended successfully"),
				Err(x) => console_error!(
					"epoxy: wisp multiplexor task ended with an error: {} {:?}",
					x,
					x
				),
			}
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
				let stream = mux.new_stream(stream_type, host, port).await?;
				Ok(stream)
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
			.into_async_rw())
	}

	pub async fn get_tls_stream(
		&self,
		host: String,
		port: u16,
		http: bool,
	) -> Result<ProviderTlsAsyncRW, EpoxyError> {
		let stream = self
			.get_asyncread(StreamType::Tcp, host.clone(), port)
			.await?;
		let connector = TlsConnector::from(if http {
			self.h2_config.clone()
		} else {
			self.client_config.clone()
		});
		let ret = connector
			.connect(host.try_into()?, stream)
			.into_fallible()
			.await;
		match ret {
			Ok(stream) => {
				let h2_negotiated = stream
					.get_ref()
					.1
					.alpn_protocol()
					.is_some_and(|x| x == "h2".as_bytes());
				Ok(IgnoreCloseNotify {
					inner: stream.into(),
					h2_negotiated,
				})
			}
			Err((err, stream)) => {
				if matches!(err.kind(), ErrorKind::UnexpectedEof) {
					// maybe actually a wisp error?
					if let Some(reason) = stream
						.get_close_reason()
						.filter(|reason| *reason != CloseReason::Unknown)
					{
						return Err(EpoxyError::WispCloseReason(reason, err));
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
		let conn = Connected::new();
		if let Either::Left(tls_stream) = &self.inner {
			if tls_stream.h2_negotiated {
				conn.negotiated_h2()
			} else {
				conn
			}
		} else {
			conn
		}
	}
}

#[derive(Clone)]
pub struct StreamProviderService(pub Arc<StreamProvider>);

impl StreamProviderService {
	async fn connect(self, req: hyper::Uri) -> Result<HyperIo, EpoxyError> {
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
		Ok(HyperIo {
			inner: match scheme {
				"https" => Either::Left(self.0.get_tls_stream(host, port, true).await?),
				"wss" => Either::Left(self.0.get_tls_stream(host, port, false).await?),
				"http" | "ws" => {
					Either::Right(self.0.get_asyncread(StreamType::Tcp, host, port).await?)
				}
				_ => return Err(EpoxyError::InvalidUrlScheme(Some(scheme.to_string()))),
			},
		})
	}
}

impl ConnectSvc for StreamProviderService {
	type Connection = HyperIo;
	type Error = EpoxyError;
	type Future = impl Future<Output = Result<Self::Connection, Self::Error>> + Send;

	fn connect(self, req: hyper::Uri) -> Self::Future {
		SendWrapper::new(Box::pin(self.connect(req)))
	}
}
