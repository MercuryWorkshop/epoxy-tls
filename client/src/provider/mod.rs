use std::{
	collections::HashMap,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, future::Either, lock::Mutex};
use futures_rustls::{
	TlsConnector,
	client::TlsStream,
	rustls::{
		CipherSuite, ClientConfig, RootCertStore,
		chrome::ClientHelloProfile,
		crypto::ring::{cipher_suite, kx_group},
	},
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
pub mod wisp;

#[derive(Clone)]
pub struct ProviderServiceReq {
	pub host: String,
	pub port: u16,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum TlsAlpnMode {
	None,
	HttpAuto,
	Http1Only,
	Custom(Vec<String>),
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
/// Maps rustls's "peer closed connection without sending TLS close_notify"
/// error to a clean EOF.
///
/// rustls reports a missing close_notify as [`std::io::ErrorKind::UnexpectedEof`],
/// and nothing else on this read path does. close_notify only guards against
/// truncation attacks, which require forging the underlying transport's EOF —
/// but the TLS stream runs inside a wisp mux stream, whose framed close already
/// provides a trustworthy end-of-stream signal. So a missing close_notify here
/// is benign and can be treated as a normal EOF.
fn map_close_notify(x: std::io::Result<usize>) -> std::io::Result<usize> {
	match x {
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
		other => other,
	}
}

impl AsyncRead for ProviderEncryptedStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().stream.poll_read(cx, buf).map(map_close_notify)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project()
			.stream
			.poll_read_vectored(cx, bufs)
			.map(map_close_notify)
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

type StreamProviderBackendService =
	BoxProviderService<ProviderServiceReq, ProviderUnencryptedStream, EpoxyError>;

pub struct StreamProvider {
	service: StreamProviderBackendService,

	configs: Mutex<HashMap<TlsAlpnMode, Arc<ClientConfig>>>,
}

/// Chrome 155's trust-anchor ID list, copied from its own ClientHello.
///
/// Opaque on purpose: nothing here reads the reply, so the contents only
/// have to be the ones a Chrome of this version would send.
const TRUST_ANCHOR_IDS: [u8; 186] = [
	0x00, 0xb8, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e, 0x05, 0x82,
	0xdf, 0x13, 0x02, 0x0f, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x12, 0x05, 0x82, 0xdf, 0x13,
	0x02, 0x13, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x14, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b,
	0x2d, 0x01, 0x07, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08, 0x08, 0x83,
	0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d,
	0x01, 0x0a, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b, 0x08, 0x83, 0x9a,
	0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01,
	0x0d, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12, 0x08, 0x83, 0x9a, 0x64,
	0x8c, 0x9b, 0x2d, 0x01, 0x13, 0x04, 0xd6, 0x79, 0x09, 0x01, 0x04, 0xd6, 0x79, 0x09,
	0x04, 0x04, 0xd6, 0x79, 0x09, 0x05, 0x04, 0xd6, 0x79, 0x09, 0x06, 0x04, 0xd6, 0x79,
	0x09, 0x07, 0x04, 0xd6, 0x79, 0x09, 0x08, 0x04, 0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6,
	0x79, 0x09, 0x0b, 0x04, 0xd6, 0x79, 0x09, 0x0c, 0x04, 0xd6, 0x79, 0x09, 0x0d, 0x04,
	0xd6, 0x79, 0x09, 0x0f
];

/// A GREASE `encrypted_client_hello`, shaped like Chrome's.
///
/// Not a real ECH offer: the `enc` and `payload` are random, so a server with
/// an ECH config will find the config id unknown and carry on with the outer
/// ClientHello, which is exactly what Chrome relies on when it greases.
fn grease_ech() -> Vec<u8> {
	let mut out = vec![
		0x00, // ECHClientHello type: outer
		0x00, 0x01, // kdf_id: HKDF-SHA256
		0x00, 0x01, // aead_id: AES-128-GCM
	];
	let mut random = [0u8; 1 + 32 + 128];
	getrandom::fill(&mut random).expect("no randomness for a greased ech");

	out.push(random[0]); // config_id
	out.extend_from_slice(&[0x00, 0x20]); // enc: 32 bytes, an X25519 share
	out.extend_from_slice(&random[1..33]);
	out.extend_from_slice(&[0x00, 0x80]); // payload: 128 bytes
	out.extend_from_slice(&random[33..]);

	out
}

impl StreamProvider {
	fn create_client_config(
		alpn_protocols: Option<Vec<Vec<u8>>>,
	) -> Result<Arc<ClientConfig>, EpoxyError> {
		let mut provider = futures_rustls::rustls::crypto::ring::default_provider();
		// The order these are offered in is part of the ClientHello, and the
		// ClientHello is what an anti-bot service reads to decide whether the
		// client is the browser its User-Agent claims to be. rustls's own order
		// puts AES-256 first; Chrome puts AES-128 first, then pairs each AEAD
		// ECDSA-before-RSA.
		//
		// These are the nine Chrome offers that rustls can actually negotiate.
		// The other six are added by the client-hello profile below, which is
		// what the patched rustls exists for.
		provider.cipher_suites = vec![
			cipher_suite::TLS13_AES_128_GCM_SHA256,
			cipher_suite::TLS13_AES_256_GCM_SHA384,
			cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
			cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		];
		// Chrome's supported_groups are X25519MLKEM768, x25519, secp256r1,
		// secp384r1. The ring provider has no ML-KEM, so the post-quantum group
		// is missing and the rest are in Chrome's order.
		provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
		let provider = Arc::new(provider);
		let mut client_config = ClientConfig::builder_with_provider(provider.clone())
			.with_safe_default_protocol_versions()?
			.with_root_certificates(
				TLS_SERVER_ROOTS
					.iter()
					.chain(EXTRA_TLS_SERVER_ROOTS.iter())
					.cloned()
					.collect::<RootCertStore>(),
			)
			.with_no_client_auth();

		client_config.client_hello_profile = Self::chrome_profile();

		if let Some(protocols) = alpn_protocols {
			client_config.alpn_protocols = protocols;
		}

		Ok(Arc::new(client_config))
	}

	/// The parts of Chrome 155's ClientHello that rustls has no reason to send.
	///
	/// Measured against a direct load by the same Chromium build, read back
	/// from tls.peet.ws (`runway/src/sbxdiff/pages/tlsfp.html`).
	///
	/// Cloudflare branches on this. Running stock Chromium with
	/// `--cipher-suite-blacklist=0x1301,0x1302,0x1303` -- which changes the
	/// handshake and nothing above it -- moves it off the `jsd` challenge and
	/// onto the `brunhild`/`pat`/`ci` one, which is the branch a rustls client
	/// gets. So this is not cosmetic: without it the proxy is a different
	/// client to Cloudflare however exactly its headers match.
	fn chrome_profile() -> ClientHelloProfile {
		ClientHelloProfile {
			// Offered and never selected: both ends pick TLS 1.3, where none of
			// these apply. They are in the list because JA3 and JA4 hash the
			// list -- nine suites where a browser sends fifteen is visible
			// whatever the nine are.
			extra_cipher_suites: vec![
				CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
				CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
				CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
				CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
			],
			extra_extensions: vec![
				// ALPS (application_settings), the v2 codepoint. Chrome offers
				// `h2` and acts on the reply; we only have to be seen offering
				// it. Payload is a one-entry ALPN-shaped list.
				(17613, vec![0x00, 0x03, 0x02, b'h', b'2']),
				// signed_certificate_timestamp, empty -- a request, not an
				// offer, so there is nothing to get wrong.
				(18, vec![]),
				// renegotiation_info, empty. Replaces the SCSV below, the way a
				// browser does it.
				(0xff01, vec![0x00]),
				// TLS flags (draft-ietf-tls-tlsflags). Chrome sends an empty
				// flag set.
				(4832, vec![0x00, 0x00]),
				// Trust anchor IDs (draft-ietf-tls-trust-anchor-ids), Chrome's
				// list copied verbatim from its own hello. The server replies
				// with nothing we read; being seen to offer it is the point.
				(51764, TRUST_ANCHOR_IDS.to_vec()),
				// GREASE ECH (encrypted_client_hello, outer form). Chrome sends
				// one of these on every connection it has no real ECH config
				// for, which is most of them -- it exists so that a network that
				// sees ECH cannot tell a client that is using it from one that
				// is not. It was the LAST thing separating this hello from
				// Chromium's: with it the offered extension set matches, and a
				// JA4 that matches no browser at all is as readable as one that
				// matches curl.
				//
				// Contents are shaped, not meaningful: outer type, HKDF-SHA256
				// with AES-128-GCM, a config id, a 32-byte X25519 `enc`, and a
				// payload. Nothing reads the reply -- that is what makes it
				// GREASE rather than ECH.
				(0xfe0d, grease_ech()),
			],
			// Chrome's, in Chrome's order, minus its leading GREASE entry.
			// 0x0904..0x0906 are ML-DSA, which nothing here can verify -- see
			// the field's own note on why that is fine.
			signature_schemes: vec![
				0x0904, 0x0905, 0x0906, // ML-DSA-44 / 65 / 87
				0x0403, // ecdsa_secp256r1_sha256
				0x0804, // rsa_pss_rsae_sha256
				0x0401, // rsa_pkcs1_sha256
				0x0503, // ecdsa_secp384r1_sha384
				0x0805, // rsa_pss_rsae_sha384
				0x0501, // rsa_pkcs1_sha384
				0x0806, // rsa_pss_rsae_sha512
				0x0601, // rsa_pkcs1_sha512
			],
			// Chrome's own order, minus the GREASE and ECH entries it also
			// sends. Anything present but unnamed here keeps a randomized
			// position after these, which is what rustls would have done with
			// all of them.
			extension_order: vec![
				17613, // application_settings
				11,    // ec_point_formats
				16,    // ALPN
				51764, // trust anchor IDs
				51,    // key_share
				5,     // status_request
				35,    // session_ticket
				0,     // server_name
				10,    // supported_groups
				45,    // psk_key_exchange_modes
				13,    // signature_algorithms
				0xff01, // renegotiation_info
				43,    // supported_versions
				4832,  // TLS flags
				27,    // compress_certificate
				18,    // signed_certificate_timestamp
				23,    // extended_master_secret
			],
			// Chrome signals renegotiation with the extension above, not the
			// SCSV, and the SCSV is inside the hashed cipher list.
			// EMPTY, and the reason is worth keeping.
			//
			// Chrome offers X25519MLKEM768 (0x11ec) ahead of the classical
			// curves and the ring provider has no ML-KEM, so the obvious move is
			// to advertise it without being able to complete it -- the same
			// trade the cipher list makes. tls.peet.ws accepts that and the
			// group shows up in JA3's fourth field, matching Chrome exactly.
			//
			// Cloudflare does not accept it. It picks the post-quantum group and
			// asks for a key share with a HelloRetryRequest, which this client
			// cannot answer: `IllegalHelloRetryRequestWithUnofferedNamedGroup`,
			// and the connection is dead before any HTTP. A server that wants
			// the group really does ask for it.
			//
			// Nothing is lost where it counts. JA4 hashes the cipher list and
			// the extension list; `supported_groups` is one extension whose
			// PRESENCE it counts and whose contents it does not, so the JA4 is
			// identical either way. Only JA3's curve field differs, and JA3 is
			// the fingerprint Chrome already makes unstable by permuting its
			// extension order.
			extra_named_groups: vec![],
			suppress_renegotiation_scsv: true,
		}
	}

	async fn get_client_config(
		&self,
		alpn_mode: TlsAlpnMode,
	) -> Result<Arc<ClientConfig>, EpoxyError> {
		let mut configs = self.configs.lock().await;
		match configs.entry(alpn_mode) {
			std::collections::hash_map::Entry::Occupied(val) => Ok(val.get().clone()),
			std::collections::hash_map::Entry::Vacant(val) => {
				let alpn_protocols = match val.key() {
					TlsAlpnMode::None => None,
					TlsAlpnMode::HttpAuto => {
						#[cfg(feature = "full")]
						let protocols =
							vec!["h2".as_bytes().to_vec(), "http/1.1".as_bytes().to_vec()];
						#[cfg(not(feature = "full"))]
						let protocols = vec!["http/1.1".as_bytes().to_vec()];
						Some(protocols)
					}
					TlsAlpnMode::Http1Only => Some(vec!["http/1.1".as_bytes().to_vec()]),
					TlsAlpnMode::Custom(protocols) => {
						Some(protocols.iter().map(|x| x.as_bytes().to_vec()).collect())
					}
				};

				let config = Self::create_client_config(alpn_protocols)?;

				Ok(val.insert(config).clone())
			}
		}
	}

	pub fn new(service: StreamProviderBackendService) -> Result<Self, EpoxyError> {
		Ok(Self {
			service,
			configs: Mutex::new(HashMap::new()),
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
		let connector = TlsConnector::from(self.get_client_config(alpn).await?);

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
