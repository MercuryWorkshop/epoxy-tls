use std::{borrow::Cow, convert::Infallible, sync::Arc};

use bytes::Bytes;
use futures::{
	AsyncReadExt, TryStreamExt,
	stream::{AbortHandle, Abortable},
};
use http::{
	HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri, Version, header,
	request, response,
};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::ext::{HeaderCaseMap, ReasonPhrase};
use js_sys::{Array, Uint8Array};
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::{
	follow_redirect::{self, FollowRedirectLayer, RequestUri},
	set_header::SetRequestHeaderLayer,
};
use wasm_bindgen::{
	JsCast,
	prelude::{Closure, wasm_bindgen},
};
use web_sys::AbortSignal;

#[cfg(feature = "full")]
use hyper::upgrade;
#[cfg(feature = "full")]
use tower::Layer;

use crate::{
	EpoxyError, EpoxyJsValErrorExt,
	http::{BoxError, EpoxyBody, HyperClient, HyperRequest, build_hyper_client},
	js_socket::{
		JsSocket, JsTlsSocket, TlsStreamInfo, create_asyncread_js_socket,
		create_asyncread_js_tls_socket,
	},
	js_types::RawHeaders,
	provider::{StreamProvider, StreamProviderService, TlsAlpnMode, service::WasmProvider},
};

#[wasm_bindgen(inline_js = "
export function ws_key() {
	let key = new Uint8Array(16);
	crypto.getRandomValues(key);
	return btoa(String.fromCharCode.apply(null, key));
}
export function ws_protocol() {
      let key = new Uint8Array(16);
      crypto.getRandomValues(key);
      return Array.from(key, x => x.toString(16).padStart(2, '0')).join('');
}
")]
extern "C" {
	pub fn ws_key() -> String;
	pub fn ws_protocol() -> String;
}

#[wasm_bindgen]
pub enum Redirect {
	Follow,
	Manual,
	Error,
}
#[derive(Clone)]
pub enum RedirectPolicy {
	Follow {
		remaining: usize,
		filter: follow_redirect::policy::FilterCredentials,
	},
	Manual,
	Error,
}
impl Redirect {
	pub fn into_policy(self, limit: usize) -> RedirectPolicy {
		match self {
			Self::Follow => RedirectPolicy::Follow {
				remaining: limit,
				filter: follow_redirect::policy::FilterCredentials::new(),
			},
			Self::Manual => RedirectPolicy::Manual,
			Self::Error => RedirectPolicy::Error,
		}
	}
}
impl follow_redirect::policy::Policy<EpoxyBody, EpoxyError> for RedirectPolicy {
	fn redirect(
		&mut self,
		attempt: &follow_redirect::policy::Attempt<'_>,
	) -> Result<follow_redirect::policy::Action, EpoxyError> {
		match self {
			Self::Follow { remaining, filter } => {
				let _ = follow_redirect::policy::Policy::<EpoxyBody, Infallible>::redirect(
					filter, attempt,
				); // always returns Ok(Follow)

				if *remaining > 0 {
					*remaining -= 1;
					Ok(follow_redirect::policy::Action::Follow)
				} else {
					Err(EpoxyError::TooManyRedirects)
				}
			}
			Self::Manual => Ok(follow_redirect::policy::Action::Stop),
			Self::Error => Err(EpoxyError::RedirectDisallowed),
		}
	}

	fn on_request(&mut self, request: &mut http::Request<EpoxyBody>) {
		if let RedirectPolicy::Follow { filter, .. } = self {
			follow_redirect::policy::Policy::<EpoxyBody, Infallible>::on_request(filter, request);
		}
	}

	fn clone_body(&self, body: &EpoxyBody) -> Option<EpoxyBody> {
		Some(body.clone())
	}
}

#[wasm_bindgen]
pub struct ClientReqBuilder {
	builder: Option<request::Builder>,
	case: HeaderCaseMap,
}
#[wasm_bindgen]
impl ClientReqBuilder {
	#[wasm_bindgen(constructor)]
	pub fn new() -> Self {
		Self {
			builder: Some(request::Request::builder()),
			case: HeaderCaseMap::default(),
		}
	}

	fn modify(
		&mut self,
		func: impl FnOnce(request::Builder) -> Result<request::Builder, EpoxyError>,
	) -> Result<(), EpoxyError> {
		let take = self.builder.take();
		self.builder.replace(func(take.unwrap())?);

		Ok(())
	}

	pub fn method(&mut self, method: &str) -> Result<(), EpoxyError> {
		self.modify(|x| Ok(x.method(Method::try_from(method)?)))
	}

	pub fn uri(&mut self, uri: String) -> Result<(), EpoxyError> {
		self.modify(|x| Ok(x.uri(Uri::try_from(uri)?)))
	}

	pub fn header(&mut self, key: String, val: String) -> Result<(), EpoxyError> {
		let name = HeaderName::try_from(&key)?;
		self.case.append(name.clone(), key.into_bytes().into());
		self.modify(|x| Ok(x.header(name, HeaderValue::try_from(val)?)))
	}

	fn take(mut self) -> request::Builder {
		let builder = self.builder.take().unwrap();
		builder.extension(self.case)
	}
}

#[wasm_bindgen]
pub struct ClientResponse {
	status: Option<StatusCode>,
	status_text: Option<String>,
	uri: Option<Uri>,
	headers: Option<HeaderMap>,
	header_case: Option<HeaderCaseMap>,
	body: Option<HyperResponseBody>,
}
#[wasm_bindgen]
impl ClientResponse {
	pub fn status(&mut self) -> u16 {
		let status = self.status.take().unwrap();
		status.as_u16()
	}

	pub fn status_text(&mut self) -> String {
		self.status_text.take().unwrap()
	}

	pub fn uri(&mut self) -> String {
		self.uri.take().unwrap().to_string()
	}

	pub fn headers(&mut self) -> RawHeaders {
		let headers = self.headers.take().unwrap();
		let header_case = self
			.header_case
			.take()
			.unwrap_or_else(|| HeaderCaseMap::default());
		let out = Array::new();

		for name in headers.keys() {
			let mut names = header_case.get_all_internal(name);

			for value in headers.get_all(name) {
				let name = names
					.next()
					.map(|x| String::from_utf8_lossy(x))
					.unwrap_or_else(|| Cow::Borrowed(name.as_str()));

				let arr = Array::new();
				arr.set(0, name.as_ref().into());
				arr.set(1, Uint8Array::new_from_slice(value.as_bytes()).into());
				out.push(&arr.into());
			}
		}

		out.unchecked_into()
	}

	pub fn body(&mut self) -> web_sys::ReadableStream {
		let body = self.body.take().unwrap();

		wasm_streams::ReadableStream::from_stream(
			body.into_data_stream()
				.map_ok(|x| Uint8Array::new_from_slice(&x).into())
				.map_err(|x| EpoxyError::from_box_error(x).into()),
		)
		.into_raw()
	}
}

type HyperResponseBody = impl Body<Data = Bytes, Error = BoxError>;

#[wasm_bindgen]
pub struct Client {
	provider: Arc<StreamProvider>,
	hyper: HyperClient,
	hyper_h1: HyperClient,
	redirect_limit: usize,
	ua: HeaderValue,
}

#[wasm_bindgen]
impl Client {
	#[define_opaque(HyperResponseBody)]
	fn build_client(
		&self,
		redirect: Redirect,
		h1_only: bool,
	) -> impl Service<HyperRequest, Response = Response<HyperResponseBody>, Error = EpoxyError> {
		let hyper = if h1_only {
			self.hyper_h1.clone()
		} else {
			self.hyper.clone()
		};

		// The override sits INSIDE the decompression layer, so it rewrites the
		// `accept-encoding` that layer just added rather than being overwritten
		// by it. Same encodings -- the decoder set is what the Cargo.toml
		// comment says it is -- spelled the way Chromium 155 spells them.
		//
		// `gzip,deflate,br` is what tower-http emits and is a fingerprint in
		// itself: no zstd, and no spaces after the commas. Measured against a
		// live Chromium over HTTP/2, every request it makes carries
		// `gzip, deflate, br, zstd`, navigation and subresource alike.
		#[cfg(feature = "full")]
		let hyper = tower_http::decompression::DecompressionLayer::new().layer(
			SetRequestHeaderLayer::overriding(
				header::ACCEPT_ENCODING,
				HeaderValue::from_static("gzip, deflate, br, zstd"),
			)
			.layer(hyper),
		);
		#[cfg(not(feature = "full"))]
		let hyper = hyper
			.map_response(|response| response.map(|body| body.map_err(|err| BoxError::from(err))));

		ServiceBuilder::new()
			.layer(FollowRedirectLayer::with_policy(
				redirect.into_policy(self.redirect_limit),
			))
			.layer(SetRequestHeaderLayer::if_not_present(
				header::ACCEPT,
				HeaderValue::from_static("*/*"),
			))
			.layer(SetRequestHeaderLayer::if_not_present(
				header::USER_AGENT,
				self.ua.clone(),
			))
			.service(hyper)
	}

	#[wasm_bindgen(constructor)]
	pub fn new(
		backend: WasmProvider,
		redirect_limit: usize,
		ua: String,
	) -> Result<Self, EpoxyError> {
		let provider = Arc::new(StreamProvider::new(backend.0)?);
		let hyper = build_hyper_client(StreamProviderService::auto(provider.clone()));
		let hyper_h1 = build_hyper_client(StreamProviderService::h1_only(provider.clone()));

		Ok(Self {
			hyper,
			hyper_h1,
			provider,
			redirect_limit,
			ua: HeaderValue::from_str(&ua)?,
		})
	}

	pub fn set_ua(&mut self, ua: String) -> Result<(), EpoxyError> {
		self.ua = HeaderValue::from_str(&ua)?;

		Ok(())
	}
	pub fn get_ua(&mut self) -> String {
		// can only be set via a string
		self.ua.to_str().unwrap().to_string()
	}

	fn get_status_text(parts: &response::Parts) -> String {
		parts
			.extensions
			.get::<ReasonPhrase>()
			.map(|x| String::from_utf8_lossy(x.as_bytes()).to_string())
			.or((parts.version > Version::HTTP_11).then(|| String::new())) // should this be here?
			.unwrap_or(parts.status.canonical_reason().unwrap_or("").to_string())
	}

	async fn __request(
		&self,
		builder: ClientReqBuilder,
		redirect: Redirect,
		body: Option<web_sys::ReadableStream>,
		length: Option<u64>,
	) -> Result<ClientResponse, EpoxyError> {
		let body = body
			.map(|x| EpoxyBody::new(x, length))
			.unwrap_or(EpoxyBody::Empty);
		let request = builder.take().body(body)?;

		let client = self.build_client(redirect, false);
		let response = client.oneshot(request).await?;
		let (mut parts, body) = response.into_parts();
		let status_text = Self::get_status_text(&parts);

		let res = ClientResponse {
			status: Some(parts.status),
			status_text: Some(status_text),
			uri: Some(parts.extensions.remove::<RequestUri>().unwrap().0),
			headers: Some(parts.headers),
			header_case: parts.extensions.remove::<HeaderCaseMap>(),
			body: Some(body),
		};

		Ok(res)
	}

	pub async fn request(
		&self,
		builder: ClientReqBuilder,
		abort: AbortSignal,
		redirect: Redirect,
		body: Option<web_sys::ReadableStream>,
		length: Option<u64>,
	) -> Result<ClientResponse, EpoxyError> {
		let (handle, reg) = AbortHandle::new_pair();
		let on_abort_handle = handle.clone();
		let closure = Closure::<dyn FnMut()>::new(move || on_abort_handle.abort());
		abort
			.add_event_listener_with_callback("abort", closure.as_ref().unchecked_ref())
			.js_error()?;

		if abort.aborted() {
			handle.abort();
		}

		let ret = Abortable::new(self.__request(builder, redirect, body, length), reg).await;

		let _ =
			abort.remove_event_listener_with_callback("abort", closure.as_ref().unchecked_ref());

		ret.map_err(|_| EpoxyError::Aborted).flatten()
	}

	#[cfg(feature = "full")]
	pub async fn upgrade_ws(
		&self,
		builder: ClientReqBuilder,
		protocols: Vec<String>,
	) -> Result<crate::websocket::WsUpgrade, EpoxyError> {
		let key = ws_key();
		let expected_accept = crate::websocket::websocket_accept_value(&key);
		let key = HeaderValue::try_from(key)?;

		let request = builder
			.take()
			.version(Version::HTTP_11)
			.body(EpoxyBody::Empty)?;
		let protocol = (!protocols.is_empty())
			.then(|| HeaderValue::try_from(protocols.join(", ")))
			.transpose()?;

		let client = self.build_client(Redirect::Error, true);
		let client = ServiceBuilder::new()
			.layer(SetRequestHeaderLayer::overriding(
				header::CONNECTION,
				HeaderValue::from_static("Upgrade"),
			))
			.layer(SetRequestHeaderLayer::overriding(
				header::UPGRADE,
				HeaderValue::from_static("websocket"),
			))
			.layer(SetRequestHeaderLayer::overriding(
				header::SEC_WEBSOCKET_KEY,
				|_: &http::Request<EpoxyBody>| Some(key.clone()),
			))
			.layer(SetRequestHeaderLayer::overriding(
				header::SEC_WEBSOCKET_VERSION,
				HeaderValue::from_static("13"),
			))
			.layer(SetRequestHeaderLayer::overriding(
				header::SEC_WEBSOCKET_PROTOCOL,
				|_: &http::Request<EpoxyBody>| protocol.clone(),
			))
			.service(client);

		let mut response = client.oneshot(request).await?;
		let on_upgrade = upgrade::on(&mut response);
		let (mut parts, _body) = response.into_parts();
		let status_text = Self::get_status_text(&parts);

		crate::websocket::verify_upgrade_response(&parts, &protocols, &expected_accept)?;

		let res = ClientResponse {
			status: Some(parts.status),
			status_text: Some(status_text),
			uri: Some(parts.extensions.remove::<RequestUri>().unwrap().0),
			headers: Some(parts.headers),
			header_case: parts.extensions.remove::<HeaderCaseMap>(),
			body: None,
		};

		let (read, write) = crate::websocket::websocket_streams(on_upgrade.await?);

		let out = Array::new();
		out.set(0, res.into());
		out.set(1, read.into());
		out.set(2, write.into());

		Ok(out.unchecked_into())
	}

	pub async fn connect(
		&self,
		host: String,
		port: u16,
		buffer_size: usize,
	) -> Result<JsSocket, EpoxyError> {
		self.provider
			.get_stream(host, port)
			.await
			.map(|x| create_asyncread_js_socket(x.read, buffer_size, x.write))
	}

	pub async fn connect_tls(
		&self,
		host: String,
		port: u16,
		buffer_size: usize,
		alpn: Option<Vec<String>>,
	) -> Result<JsTlsSocket, EpoxyError> {
		let alpn = match alpn {
			Some(protocols) if !protocols.is_empty() => TlsAlpnMode::Custom(protocols),
			_ => TlsAlpnMode::None,
		};

		self.provider
			.get_tls_stream(host, port, alpn)
			.await
			.map(|x| {
				let conn = x.stream.get_ref().1;
				let negotiated_protocol = conn
					.alpn_protocol()
					.map(|x| String::from_utf8_lossy(x).into_owned());
				// `Debug` is compiled out by `-Zfmt-debug=none`; `as_str` is a
				// `stringify!`-based match, so it survives.
				let protocol_version = conn.protocol_version().map(|version| {
					version
						.as_str()
						.map_or_else(|| format!("0x{:04x}", u16::from(version)), str::to_string)
				});
				let cipher_suite = conn.negotiated_cipher_suite().map(|suite| {
					let suite = suite.suite();
					suite
						.as_str()
						.map_or_else(|| format!("0x{:04x}", u16::from(suite)), str::to_string)
				});
				let peer_certificates = conn
					.peer_certificates()
					.map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect());
				let info = TlsStreamInfo::new(
					negotiated_protocol,
					protocol_version,
					cipher_suite,
					peer_certificates,
				);
				let (rx, tx) = x.split();
				create_asyncread_js_tls_socket(rx, buffer_size, tx, info)
			})
	}
}
