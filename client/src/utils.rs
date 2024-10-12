use std::{
	io::ErrorKind,
	pin::Pin,
	task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{buf::UninitSlice, BufMut, Bytes, BytesMut};
use futures_rustls::{
	rustls::{
		self,
		client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
		crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
		DigitallySignedStruct, SignatureScheme,
	},
	TlsStream,
};
use futures_util::{ready, AsyncRead, AsyncWrite, Future, Stream, StreamExt, TryStreamExt};
use http::{HeaderValue, Uri};
use hyper::{body::Body, rt::Executor};
use js_sys::{Array, ArrayBuffer, Function, JsString, Object, Uint8Array};
use pin_project_lite::pin_project;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use send_wrapper::SendWrapper;
use wasm_bindgen::{prelude::*, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_streams::{readable::IntoStream, ReadableStream};
use web_sys::WritableStreamDefaultWriter;
use wisp_mux::{
	ws::{Frame, LockedWebSocketWrite, Payload, WebSocketRead, WebSocketWrite},
	WispError,
};

use crate::{stream_provider::ProviderUnencryptedAsyncRW, EpoxyError};

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(js_namespace = console, js_name = log)]
	pub fn js_console_log(s: &str);
}

#[macro_export]
macro_rules! console_log {
	($($expr:expr),*) => {
		$crate::utils::js_console_log(&format!($($expr),*));
	};
}

pub trait UriExt {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError>;
}

impl UriExt for Uri {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError> {
		let new_uri = location.to_str()?.parse::<hyper::Uri>()?;
		let mut new_parts: http::uri::Parts = new_uri.into();
		if new_parts.scheme.is_none() {
			new_parts.scheme = self.scheme().cloned();
		}
		if new_parts.authority.is_none() {
			new_parts.authority = self.authority().cloned();
		}

		Ok(Uri::from_parts(new_parts)?)
	}
}

#[derive(Clone)]
pub struct WasmExecutor;

impl<F> Executor<F> for WasmExecutor
where
	F: Future + Send + 'static,
	F::Output: Send + 'static,
{
	fn execute(&self, future: F) {
		wasm_bindgen_futures::spawn_local(async move {
			let _ = future.await;
		});
	}
}

pin_project! {
	pub struct IncomingBody {
		#[pin]
		incoming: hyper::body::Incoming,
	}
}

impl IncomingBody {
	pub fn new(incoming: hyper::body::Incoming) -> IncomingBody {
		IncomingBody { incoming }
	}
}

impl Stream for IncomingBody {
	type Item = std::io::Result<Bytes>;
	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.project().incoming.poll_frame(cx).map(|x| {
			x.map(|x| {
				x.map_err(std::io::Error::other).and_then(|x| {
					x.into_data().map_err(|_| {
						std::io::Error::other("trailer frame recieved; not implemented")
					})
				})
			})
		})
	}
}

pin_project! {
	#[derive(Debug)]
	pub struct ReaderStream<R> {
		#[pin]
		reader: Option<R>,
		buf: BytesMut,
		capacity: usize,
	}
}

impl<R: AsyncRead> ReaderStream<R> {
	pub fn new(reader: R, capacity: usize) -> Self {
		ReaderStream {
			reader: Some(reader),
			buf: BytesMut::new(),
			capacity,
		}
	}
}

pub fn poll_read_buf<T: AsyncRead + ?Sized, B: BufMut>(
	io: Pin<&mut T>,
	cx: &mut Context<'_>,
	buf: &mut B,
) -> Poll<std::io::Result<usize>> {
	if !buf.has_remaining_mut() {
		return Poll::Ready(Ok(0));
	}

	let n = {
		let dst = buf.chunk_mut();

		let dst = unsafe { std::mem::transmute::<&mut UninitSlice, &mut [u8]>(dst) };
		ready!(io.poll_read(cx, dst)?)
	};

	unsafe {
		buf.advance_mut(n);
	}

	Poll::Ready(Ok(n))
}

impl<R: AsyncRead> Stream for ReaderStream<R> {
	type Item = std::io::Result<Bytes>;
	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let mut this = self.as_mut().project();

		let reader = match this.reader.as_pin_mut() {
			Some(r) => r,
			None => return Poll::Ready(None),
		};

		if this.buf.capacity() == 0 {
			this.buf.reserve(*this.capacity);
		}

		match poll_read_buf(reader, cx, &mut this.buf) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Err(err)) => {
				self.project().reader.set(None);
				Poll::Ready(Some(Err(err)))
			}
			Poll::Ready(Ok(0)) => {
				self.project().reader.set(None);
				Poll::Ready(None)
			}
			Poll::Ready(Ok(_)) => {
				let chunk = this.buf.split();
				Poll::Ready(Some(Ok(chunk.freeze())))
			}
		}
	}
}

pub struct WispTransportRead {
	pub inner: SendWrapper<IntoStream<'static>>,
}

#[async_trait]
impl WebSocketRead for WispTransportRead {
	async fn wisp_read_frame(
		&mut self,
		_tx: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, wisp_mux::WispError> {
		let obj = self.inner.next().await;

		if let Some(pkt) = obj {
			let pkt =
				pkt.map_err(|x| WispError::WsImplError(Box::new(EpoxyError::wisp_transport(x))))?;
			let arr: ArrayBuffer = pkt.dyn_into().map_err(|_| {
				WispError::WsImplError(Box::new(EpoxyError::InvalidWispTransportPacket))
			})?;

			Ok(Frame::binary(Payload::Bytes(
				Uint8Array::new(&arr).to_vec().as_slice().into(),
			)))
		} else {
			Ok(Frame::close(Payload::Borrowed(&[])))
		}
	}
}

pub struct WispTransportWrite {
	pub inner: SendWrapper<WritableStreamDefaultWriter>,
}

#[async_trait]
impl WebSocketWrite for WispTransportWrite {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		SendWrapper::new(async {
			let chunk = Uint8Array::from(frame.payload.as_ref()).into();
			JsFuture::from(self.inner.write_with_chunk(&chunk))
				.await
				.map(|_| ())
				.map_err(|x| WispError::WsImplError(Box::new(EpoxyError::wisp_transport(x))))
		})
		.await
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		SendWrapper::new(JsFuture::from(self.inner.abort()))
			.await
			.map(|_| ())
			.map_err(|x| WispError::WsImplError(Box::new(EpoxyError::wisp_transport(x))))
	}
}

fn map_close_notify(x: std::io::Result<usize>) -> std::io::Result<usize> {
	match x {
		Ok(x) => Ok(x),
		Err(x) => {
			// hacky way to find if it's actually a rustls close notify error
			if x.kind() == ErrorKind::UnexpectedEof
				&& format!("{:?}", x).contains("TLS close_notify")
			{
				Ok(0)
			} else {
				Err(x)
			}
		}
	}
}

pin_project! {
	pub struct IgnoreCloseNotify {
		#[pin]
		pub inner: TlsStream<ProviderUnencryptedAsyncRW>,
	}
}

impl AsyncRead for IgnoreCloseNotify {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project()
			.inner
			.poll_read(cx, buf)
			.map(map_close_notify)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project()
			.inner
			.poll_read_vectored(cx, bufs)
			.map(map_close_notify)
	}
}

impl AsyncWrite for IgnoreCloseNotify {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().inner.poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project().inner.poll_write_vectored(cx, bufs)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().inner.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().inner.poll_close(cx)
	}
}

#[derive(Debug)]
pub struct NoCertificateVerification(CryptoProvider);

impl NoCertificateVerification {
	pub fn new(provider: CryptoProvider) -> Self {
		Self(provider)
	}
}

impl ServerCertVerifier for NoCertificateVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls12_signature(
			message,
			cert,
			dss,
			&self.0.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls13_signature(
			message,
			cert,
			dss,
			&self.0.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}

pub fn is_redirect(code: u16) -> bool {
	[301, 302, 303, 307, 308].contains(&code)
}

pub fn is_null_body(code: u16) -> bool {
	[101, 204, 205, 304].contains(&code)
}

#[wasm_bindgen(inline_js = r#"
class WebSocketStreamPonyfill {
	url;
	opened;
	closed;
	close;
	constructor(url, options = {}) {
		if (options.signal?.aborted) {
			throw new DOMException('This operation was aborted', 'AbortError');
		}
		this.url = url;
		const ws = new WebSocket(url, options.protocols ?? []);
		ws.binaryType = "arraybuffer";
		const closeWithInfo = ({ closeCode: code, reason } = {}) => ws.close(code, reason);
		this.opened = new Promise((resolve, reject) => {
			ws.onopen = () => {
				resolve({
					readable: new ReadableStream({
						start(controller) {
							ws.onmessage = ({ data }) => controller.enqueue(data);
							ws.onerror = e => controller.error(e);
						},
						cancel: closeWithInfo,
					}),
					writable: new WritableStream({
						write(chunk) { ws.send(chunk); },
						abort() { ws.close(); },
						close: closeWithInfo,
					}),
					protocol: ws.protocol,
					extensions: ws.extensions,
				});
				ws.removeEventListener('error', reject);
			};
			ws.addEventListener('error', reject);
		});
		this.closed = new Promise((resolve, reject) => {
			ws.onclose = ({ code, reason }) => {
				resolve({ closeCode: code, reason });
				ws.removeEventListener('error', reject);
			};
			ws.addEventListener('error', reject);
		});
		if (options.signal) {
			options.signal.onabort = () => ws.close();
		}
		this.close = closeWithInfo;
	}
}

export function object_get(obj, k) { 
	try {
		return obj[k]
	} catch(x) {
		return undefined
	}
};
export function object_set(obj, k, v) {
	try { obj[k] = v } catch {}
};

export async function convert_body_inner(body) {
	let req = new Request("", { method: "POST", duplex: "half", body });
	let type = req.headers.get("content-type");
	return [new Uint8Array(await req.arrayBuffer()), type];
}

export function entries_of_object_inner(obj) {
	return Object.entries(obj).map(x => x.map(String));
}

export function define_property(obj, k, v) {
	Object.defineProperty(obj, k, { value: v, writable: false });
}

export function ws_key() {
	let key = new Uint8Array(16);
	crypto.getRandomValues(key);
	return btoa(Array.from(key).map(String.fromCharCode).join(''));
}

export function from_entries(entries){
    var ret = {};
    for(var i = 0; i < entries.length; i++) ret[entries[i][0]] = entries[i][1];
    return ret;
}

async function websocket_connect(url, protocols) {
	let wss = new (typeof WebSocketStream !== "undefined" ? WebSocketStream : WebSocketStreamPonyfill)(url, { protocols: protocols });
	let {readable, writable} = await wss.opened;
	return {read: readable, write: writable};
}

export function bind_ws_connect(url, protocols) {
	return websocket_connect.bind(undefined, url, protocols);
}
"#)]
extern "C" {
	pub fn object_get(obj: &Object, key: &str) -> JsValue;
	pub fn object_set(obj: &Object, key: &str, val: JsValue);

	#[wasm_bindgen(catch)]
	async fn convert_body_inner(val: JsValue) -> Result<JsValue, JsValue>;

	fn entries_of_object_inner(obj: &Object) -> Vec<Array>;
	pub fn define_property(obj: &Object, key: &str, val: JsValue);
	pub fn ws_key() -> String;

	#[wasm_bindgen(catch)]
	pub fn from_entries(iterable: &JsValue) -> Result<Object, JsValue>;

	pub fn bind_ws_connect(url: String, protocols: Vec<String>) -> Function;
}

pub async fn convert_body(val: JsValue) -> Result<(Uint8Array, Option<String>), JsValue> {
	let req: Array = convert_body_inner(val).await?.unchecked_into();
	let str: Option<JsString> = object_truthy(req.at(1)).map(|x| x.unchecked_into());
	Ok((req.at(0).unchecked_into(), str.map(Into::into)))
}

pub fn entries_of_object(obj: &Object) -> Vec<Vec<String>> {
	entries_of_object_inner(obj)
		.into_iter()
		.map(|x| {
			x.iter()
				.map(|x| x.unchecked_into::<JsString>().into())
				.collect()
		})
		.collect()
}

pub fn asyncread_to_readablestream(
	read: Pin<Box<dyn AsyncRead>>,
	buffer_size: usize,
) -> web_sys::ReadableStream {
	ReadableStream::from_stream(
		ReaderStream::new(read, buffer_size)
			.map_ok(|x| Uint8Array::from(x.as_ref()).into())
			.map_err(|x| EpoxyError::from(x).into()),
	)
	.into_raw()
}

pub fn object_truthy(val: JsValue) -> Option<JsValue> {
	if val.is_truthy() {
		Some(val)
	} else {
		None
	}
}
