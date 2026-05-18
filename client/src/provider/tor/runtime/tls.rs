use std::{
	borrow::Cow,
	io,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_rustls::{
	TlsConnector as FuturesTlsConnector,
	client::TlsStream,
	rustls::{
		self, CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TLSError,
		SignatureScheme,
		client::{Resumption, danger},
		crypto::{self, CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
	},
};
use pin_project::pin_project;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tor_rtcompat::{
	CertifiedConn, StreamOps, TlsProvider,
	tls::{TlsAcceptorSettings, TlsConnector},
};
use webpki::EndEntityCert;

use crate::EpoxyError;

use super::net::WasmTcpStream;

/// A `TlsProvider` that wraps the JS-backed transport with `futures-rustls`,
/// using the Tor-specific "verify only that the cert is well-formed" verifier
/// from `tor_rtcompat::impls::rustls`.
#[derive(Clone)]
pub struct WasmTlsProvider {
	config: Arc<ClientConfig>,
}

impl WasmTlsProvider {
	pub fn new() -> Result<Self, EpoxyError> {
		// Match the existing crate's choice of crypto provider.
		let provider = Arc::new(rustls::crypto::ring::default_provider());
		let mut config = ClientConfig::builder_with_provider(provider.clone())
			.with_safe_default_protocol_versions()?
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(TorVerifier(
				provider.signature_verification_algorithms,
			)))
			.with_no_client_auth();

		// tor-spec: forbid TLS session resumption.
		config.resumption = Resumption::disabled();

		Ok(Self {
			config: Arc::new(config),
		})
	}
}

/// The TLS stream type produced by `WasmTlsProvider`. We need our own wrapper
/// so we can implement `CertifiedConn` and `StreamOps` for it (the bare
/// `futures_rustls` stream doesn't implement those).
#[pin_project]
pub struct WasmTlsStream {
	#[pin]
	inner: TlsStream<WasmTcpStream>,
}

impl AsyncRead for WasmTlsStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_read(cx, buf)
	}
}

impl AsyncWrite for WasmTlsStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().inner.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().inner.poll_close(cx)
	}
}

impl StreamOps for WasmTlsStream {}

impl CertifiedConn for WasmTlsStream {
	fn export_keying_material(
		&self,
		len: usize,
		label: &[u8],
		context: Option<&[u8]>,
	) -> io::Result<Vec<u8>> {
		let (_, session) = self.inner.get_ref();
		session
			.export_keying_material(vec![0_u8; len], label, context)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
	}

	fn peer_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
		let (_, session) = self.inner.get_ref();
		Ok(session
			.peer_certificates()
			.and_then(|certs| certs.first().map(|c| Cow::from(c.as_ref()))))
	}

	fn own_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
		// Client streams never present a certificate.
		Ok(None)
	}
}

pub struct WasmTlsConnector {
	connector: FuturesTlsConnector,
}

#[async_trait]
impl TlsConnector<WasmTcpStream> for WasmTlsConnector {
	type Conn = WasmTlsStream;

	async fn negotiate_unvalidated(
		&self,
		stream: WasmTcpStream,
		sni_hostname: &str,
	) -> io::Result<WasmTlsStream> {
		let name: ServerName<'_> = sni_hostname
			.try_into()
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
		let inner = self.connector.connect(name.to_owned(), stream).await?;
		Ok(WasmTlsStream { inner })
	}
}

impl TlsProvider<WasmTcpStream> for WasmTlsProvider {
	type Connector = WasmTlsConnector;
	type TlsStream = WasmTlsStream;

	type Acceptor = UnimplementedTlsAcceptor;
	type TlsServerStream = UnimplementedTlsAcceptor;

	fn tls_connector(&self) -> Self::Connector {
		WasmTlsConnector {
			connector: FuturesTlsConnector::from(Arc::clone(&self.config)),
		}
	}

	fn tls_acceptor(&self, _settings: TlsAcceptorSettings) -> io::Result<Self::Acceptor> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"WasmTlsProvider does not support running as a TLS server",
		))
	}

	fn supports_keying_material_export(&self) -> bool {
		true
	}
}

impl TlsProvider<WasmTcpStream> for super::WasmTorRuntime {
	type Connector = WasmTlsConnector;
	type TlsStream = WasmTlsStream;

	type Acceptor = UnimplementedTlsAcceptor;
	type TlsServerStream = UnimplementedTlsAcceptor;

	fn tls_connector(&self) -> Self::Connector {
		self.tls_provider().tls_connector()
	}

	fn tls_acceptor(&self, settings: TlsAcceptorSettings) -> io::Result<Self::Acceptor> {
		self.tls_provider().tls_acceptor(settings)
	}

	fn supports_keying_material_export(&self) -> bool {
		self.tls_provider().supports_keying_material_export()
	}
}

/// Stand-in TLS-server type. Tor in client mode never invokes the acceptor.
pub struct UnimplementedTlsAcceptor(void::Void);

impl AsyncRead for UnimplementedTlsAcceptor {
	fn poll_read(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		_buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		void::unreachable(self.0)
	}
}
impl AsyncWrite for UnimplementedTlsAcceptor {
	fn poll_write(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		_buf: &[u8],
	) -> Poll<io::Result<usize>> {
		void::unreachable(self.0)
	}
	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		void::unreachable(self.0)
	}
	fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		void::unreachable(self.0)
	}
}
impl StreamOps for UnimplementedTlsAcceptor {}
impl CertifiedConn for UnimplementedTlsAcceptor {
	fn export_keying_material(
		&self,
		_len: usize,
		_label: &[u8],
		_context: Option<&[u8]>,
	) -> io::Result<Vec<u8>> {
		void::unreachable(self.0)
	}
	fn peer_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
		void::unreachable(self.0)
	}
	fn own_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
		void::unreachable(self.0)
	}
}
#[async_trait]
impl TlsConnector<WasmTcpStream> for UnimplementedTlsAcceptor {
	type Conn = UnimplementedTlsAcceptor;
	async fn negotiate_unvalidated(
		&self,
		_stream: WasmTcpStream,
		_sni_hostname: &str,
	) -> io::Result<UnimplementedTlsAcceptor> {
		void::unreachable(self.0)
	}
}

/// Tor-specific "verify only that the cert is well-formed" verifier, copied
/// from `tor_rtcompat::impls::rustls` (which we cannot pull in directly because
/// it requires a Tokio/async-std/smol runtime).
#[derive(Clone, Debug)]
struct TorVerifier(WebPkiSupportedAlgorithms);

impl danger::ServerCertVerifier for TorVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer,
		_roots: &[CertificateDer],
		_server_name: &ServerName,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<danger::ServerCertVerified, TLSError> {
		// Just confirm the cert is well-formed. Real authentication happens
		// inside the Tor handshake's CERTS cell.
		let _: EndEntityCert<'_> = end_entity
			.try_into()
			.map_err(|_| TLSError::InvalidCertificate(CertificateError::BadEncoding))?;
		Ok(danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<danger::HandshakeSignatureValid, TLSError> {
		verify_tls12_signature(message, cert, dss, &self.0)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<danger::HandshakeSignatureValid, TLSError> {
		verify_tls13_signature(message, cert, dss, &self.0)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.0.supported_schemes()
	}

	fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
		None
	}
}

// Stop unused-import warnings under cfg combinations.
#[allow(dead_code)]
fn _force_provider_use(p: &CryptoProvider) -> &'static str {
	let _ = crypto::ring::default_provider();
	let _ = p;
	"unused"
}
