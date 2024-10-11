#![feature(let_chains, impl_trait_in_assoc_type)]
use std::{str::FromStr, sync::Arc};

#[cfg(feature = "full")]
use async_compression::futures::bufread as async_comp;
use bytes::Bytes;
use cfg_if::cfg_if;
#[cfg(feature = "full")]
use futures_util::future::Either;
use futures_util::TryStreamExt;
use http::{
	header::{
		InvalidHeaderName, InvalidHeaderValue, ACCEPT_ENCODING, CONNECTION, CONTENT_LENGTH,
		CONTENT_TYPE, HOST, USER_AGENT,
	},
	method::InvalidMethod,
	uri::{InvalidUri, InvalidUriParts},
	HeaderName, HeaderValue, Method, Request, Response,
};
use hyper::{body::Incoming, Uri};
use hyper_util_wasm::client::legacy::Client;
#[cfg(feature = "full")]
use io_stream::{iostream_from_asyncrw, iostream_from_stream, EpoxyIoStream};
use js_sys::{Array, Function, Object, Promise};
use send_wrapper::SendWrapper;
use stream_provider::{StreamProvider, StreamProviderService};
use thiserror::Error;
use utils::{
	asyncread_to_readablestream, bind_ws_connect, convert_body, entries_of_object,
	from_entries, is_null_body, is_redirect, object_get, object_set, object_truthy, IncomingBody,
	UriExt, WasmExecutor, WispTransportRead, WispTransportWrite,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ResponseInit, WritableStream};
#[cfg(feature = "full")]
use websocket::EpoxyWebSocket;
#[cfg(feature = "full")]
use wisp_mux::StreamType;
use wisp_mux::{
	ws::{WebSocketRead, WebSocketWrite},
	CloseReason,
};

#[cfg(feature = "full")]
mod io_stream;
mod stream_provider;
mod tokioio;
mod utils;
#[cfg(feature = "full")]
mod websocket;

type HttpBody = http_body_util::Full<Bytes>;

#[derive(Debug, Error)]
pub enum EpoxyError {
	#[error("Invalid DNS name: {0:?} ({0})")]
	InvalidDnsName(#[from] futures_rustls::rustls::pki_types::InvalidDnsNameError),
	#[error("Wisp: {0:?} ({0})")]
	Wisp(#[from] wisp_mux::WispError),
	#[error("Wisp server closed: {0}")]
	WispCloseReason(wisp_mux::CloseReason),
	#[error("IO: {0:?} ({0})")]
	Io(#[from] std::io::Error),
	#[error("HTTP: {0:?} ({0})")]
	Http(#[from] http::Error),
	#[error("Hyper client: {0:?} ({0})")]
	HyperClient(#[from] hyper_util_wasm::client::legacy::Error),
	#[error("Hyper: {0:?} ({0})")]
	Hyper(#[from] hyper::Error),
	#[error("HTTP ToStr: {0:?} ({0})")]
	ToStr(#[from] http::header::ToStrError),
	#[cfg(feature = "full")]
	#[error("Pemfile: {0:?} ({0})")]
	Pemfile(std::io::Error),
	#[cfg(feature = "full")]
	#[error("Webpki: {0:?} ({0})")]
	Webpki(#[from] webpki::Error),

	#[error("Wisp transport: {0}")]
	WispTransport(String),
	#[error("Invalid Wisp transport")]
	InvalidWispTransport,
	#[error("Invalid Wisp transport packet")]
	InvalidWispTransportPacket,
	#[error("Wisp transport already closed")]
	WispTransportClosed,

	#[cfg(feature = "full")]
	#[error("Fastwebsockets: {0:?} ({0})")]
	FastWebSockets(#[from] fastwebsockets::WebSocketError),
	#[cfg(feature = "full")]
	#[error("Invalid websocket response status code: {0} != {1}")]
	WsInvalidStatusCode(u16, u16),
	#[cfg(feature = "full")]
	#[error("Invalid websocket upgrade header: {0:?} != \"websocket\"")]
	WsInvalidUpgradeHeader(String),
	#[cfg(feature = "full")]
	#[error("Invalid websocket connection header: {0:?} != \"Upgrade\"")]
	WsInvalidConnectionHeader(String),
	#[cfg(feature = "full")]
	#[error("Invalid websocket payload, only String/ArrayBuffer accepted")]
	WsInvalidPayload,

	#[error("Invalid URL scheme")]
	InvalidUrlScheme,
	#[error("No URL host found")]
	NoUrlHost,
	#[error("No URL port found")]
	NoUrlPort,
	#[error("Invalid request body")]
	InvalidRequestBody,
	#[error("Invalid request")]
	InvalidRequest,
	#[error("Invalid payload")]
	InvalidPayload,
	#[error("Failed to construct response headers object")]
	ResponseHeadersFromEntriesFailed,
	#[error("Failed to construct response object")]
	ResponseNewFailed,
}

impl EpoxyError {
	pub fn wisp_transport(value: JsValue) -> Self {
		if let Some(err) = value.dyn_ref::<js_sys::Error>() {
			Self::WispTransport(err.to_string().into())
		} else {
			Self::WispTransport(format!("{:?}", value))
		}
	}
}

impl From<EpoxyError> for JsValue {
	fn from(value: EpoxyError) -> Self {
		JsError::from(value).into()
	}
}

impl From<InvalidUri> for EpoxyError {
	fn from(value: InvalidUri) -> Self {
		http::Error::from(value).into()
	}
}

impl From<InvalidUriParts> for EpoxyError {
	fn from(value: InvalidUriParts) -> Self {
		http::Error::from(value).into()
	}
}

impl From<InvalidHeaderName> for EpoxyError {
	fn from(value: InvalidHeaderName) -> Self {
		http::Error::from(value).into()
	}
}

impl From<InvalidHeaderValue> for EpoxyError {
	fn from(value: InvalidHeaderValue) -> Self {
		http::Error::from(value).into()
	}
}

impl From<InvalidMethod> for EpoxyError {
	fn from(value: InvalidMethod) -> Self {
		http::Error::from(value).into()
	}
}

impl From<CloseReason> for EpoxyError {
	fn from(value: CloseReason) -> Self {
		EpoxyError::WispCloseReason(value)
	}
}

#[derive(Debug)]
enum EpoxyResponse {
	Success(Response<Incoming>),
	Redirect((Response<Incoming>, http::Request<HttpBody>)),
}

#[cfg(feature = "full")]
enum EpoxyCompression {
	Brotli,
	Gzip,
}

// ugly hack. switch to serde-wasm-bindgen or a knockoff
cfg_if! {
	if #[cfg(feature = "full")] {
		#[wasm_bindgen]
		pub struct EpoxyClientOptions {
			pub wisp_v2: bool,
			pub udp_extension_required: bool,
			pub title_case_headers: bool,
			#[wasm_bindgen(getter_with_clone)]
			pub websocket_protocols: Vec<String>,
			pub redirect_limit: usize,
			#[wasm_bindgen(getter_with_clone)]
			pub user_agent: String,
			#[wasm_bindgen(getter_with_clone)]
			pub pem_files: Vec<String>,
			pub disable_certificate_validation: bool,
			pub buffer_size: usize,
		}
	} else {
		#[wasm_bindgen]
		pub struct EpoxyClientOptions {
			pub wisp_v2: bool,
			pub udp_extension_required: bool,
			pub title_case_headers: bool,
			#[wasm_bindgen(getter_with_clone)]
			pub websocket_protocols: Vec<String>,
			pub redirect_limit: usize,
			#[wasm_bindgen(getter_with_clone)]
			pub user_agent: String,
			pub disable_certificate_validation: bool,
			pub buffer_size: usize,
		}
	}
}

#[wasm_bindgen]
impl EpoxyClientOptions {
	#[wasm_bindgen(constructor)]
	pub fn new_default() -> Self {
		Self::default()
	}
}

impl Default for EpoxyClientOptions {
	fn default() -> Self {
		Self {
            wisp_v2: false,
            udp_extension_required: false,
			title_case_headers: false,
            websocket_protocols: Vec::new(),
            redirect_limit: 10,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36".to_string(),
			#[cfg(feature = "full")]
			pem_files: Vec::new(),
			disable_certificate_validation: false,
			buffer_size: 16384,
        }
	}
}

#[wasm_bindgen(getter_with_clone)]
pub struct EpoxyHandlers {
	pub onopen: Function,
	pub onclose: Function,
	pub onerror: Function,
	pub onmessage: Function,
}

#[cfg(feature = "full")]
#[wasm_bindgen]
impl EpoxyHandlers {
	#[wasm_bindgen(constructor)]
	pub fn new(
		onopen: Function,
		onclose: Function,
		onerror: Function,
		onmessage: Function,
	) -> Self {
		Self {
			onopen,
			onclose,
			onerror,
			onmessage,
		}
	}
}

fn get_stream_provider(
	func: Function,
	options: &EpoxyClientOptions,
) -> Result<StreamProvider, EpoxyError> {
	let wisp_transport = SendWrapper::new(func);
	StreamProvider::new(
		Box::new(move || {
			let wisp_transport = wisp_transport.clone();
			Box::pin(SendWrapper::new(async move {
				let transport = wisp_transport
					.call0(&JsValue::NULL)
					.map_err(EpoxyError::wisp_transport)?;

				let transport = match transport.dyn_into::<Promise>() {
					Ok(transport) => {
						let fut = JsFuture::from(transport);
						fut.await.map_err(EpoxyError::wisp_transport)?
					}
					Err(transport) => transport,
				}
				.into();

				let read = WispTransportRead {
					inner: SendWrapper::new(
						wasm_streams::ReadableStream::from_raw(
							object_get(&transport, "read").into(),
						)
						.into_stream(),
					),
				};
				let write: WritableStream = object_get(&transport, "write").into();
				let write = WispTransportWrite {
					inner: SendWrapper::new(
						write.get_writer().map_err(EpoxyError::wisp_transport)?,
					),
				};

				Ok((
					Box::new(read) as Box<dyn WebSocketRead + Send>,
					Box::new(write) as Box<dyn WebSocketWrite + Send>,
				))
			}))
		}),
		options,
	)
}

#[wasm_bindgen(inspectable)]
pub struct EpoxyClient {
	stream_provider: Arc<StreamProvider>,
	client: Client<StreamProviderService, HttpBody>,

	certs_tampered: bool,

	pub redirect_limit: usize,
	#[wasm_bindgen(getter_with_clone)]
	pub user_agent: String,
	pub buffer_size: usize,
}

#[wasm_bindgen]
impl EpoxyClient {
	#[wasm_bindgen(constructor)]
	pub fn new(wisp_url: JsValue, options: EpoxyClientOptions) -> Result<EpoxyClient, EpoxyError> {
		let stream_provider = if let Some(wisp_url) = wisp_url.as_string() {
			let wisp_uri: Uri = wisp_url.clone().try_into()?;
			if wisp_uri.scheme_str() != Some("wss") && wisp_uri.scheme_str() != Some("ws") {
				return Err(EpoxyError::InvalidUrlScheme);
			}
			let ws_protocols = options.websocket_protocols.clone();
			Arc::new(get_stream_provider(
				bind_ws_connect(wisp_url, ws_protocols),
				&options,
			)?)
		} else if let Ok(wisp_transport) = wisp_url.dyn_into::<Function>() {
			Arc::new(get_stream_provider(wisp_transport, &options)?)
		} else {
			return Err(EpoxyError::InvalidWispTransport);
		};

		let service = StreamProviderService(stream_provider.clone());
		let client = Client::builder(WasmExecutor)
			.http09_responses(true)
			.http1_title_case_headers(options.title_case_headers)
			.http1_max_headers(200)
			.build(service);

		Ok(Self {
			stream_provider,
			client,
			redirect_limit: options.redirect_limit,
			user_agent: options.user_agent,
			#[cfg(feature = "full")]
			certs_tampered: options.disable_certificate_validation || !options.pem_files.is_empty(),
			#[cfg(not(feature = "full"))]
			certs_tampered: options.disable_certificate_validation,
			buffer_size: options.buffer_size,
		})
	}

	pub async fn replace_stream_provider(&self) -> Result<(), EpoxyError> {
		self.stream_provider.replace_client().await
	}

	#[cfg(feature = "full")]
	pub async fn connect_websocket(
		&self,
		handlers: EpoxyHandlers,
		url: String,
		protocols: Vec<String>,
		headers: JsValue,
	) -> Result<EpoxyWebSocket, EpoxyError> {
		EpoxyWebSocket::connect(self, handlers, url, protocols, headers, &self.user_agent).await
	}

	#[cfg(feature = "full")]
	pub async fn connect_tcp(&self, url: String) -> Result<EpoxyIoStream, EpoxyError> {
		let url: Uri = url.try_into()?;
		let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
		let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
		let stream = self
			.stream_provider
			.get_asyncread(StreamType::Tcp, host.to_string(), port)
			.await?;
		Ok(iostream_from_asyncrw(Either::Right(stream), self.buffer_size))
	}

	#[cfg(feature = "full")]
	pub async fn connect_tls(&self, url: String) -> Result<EpoxyIoStream, EpoxyError> {
		let url: Uri = url.try_into()?;
		let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
		let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
		let stream = self
			.stream_provider
			.get_tls_stream(host.to_string(), port)
			.await?;
		Ok(iostream_from_asyncrw(Either::Left(stream), self.buffer_size))
	}

	#[cfg(feature = "full")]
	pub async fn connect_udp(&self, url: String) -> Result<EpoxyIoStream, EpoxyError> {
		let url: Uri = url.try_into()?;
		let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
		let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
		let stream = self
			.stream_provider
			.get_stream(StreamType::Udp, host.to_string(), port)
			.await?;
		Ok(iostream_from_stream(stream))
	}

	async fn send_req_inner(
		&self,
		req: http::Request<HttpBody>,
		should_redirect: bool,
	) -> Result<EpoxyResponse, EpoxyError> {
		let new_req = if should_redirect {
			Some(req.clone())
		} else {
			None
		};

		let res = self.client.request(req).await;
		match res {
			Ok(res) => {
				if is_redirect(res.status().as_u16())
					&& let Some(mut new_req) = new_req
					&& let Some(location) = res.headers().get("Location")
					&& let Ok(redirect_url) = new_req.uri().get_redirect(location)
					&& let Some(redirect_url_authority) = redirect_url.clone().authority()
				{
					*new_req.uri_mut() = redirect_url;
					new_req.headers_mut().insert(
						"Host",
						HeaderValue::from_str(redirect_url_authority.as_str())?,
					);
					Ok(EpoxyResponse::Redirect((res, new_req)))
				} else {
					Ok(EpoxyResponse::Success(res))
				}
			}
			Err(err) => Err(err.into()),
		}
	}

	async fn send_req(
		&self,
		req: http::Request<HttpBody>,
		should_redirect: bool,
	) -> Result<(hyper::Response<Incoming>, Uri, bool), EpoxyError> {
		let mut redirected = false;
		let mut current_url = req.uri().clone();
		let mut current_resp: EpoxyResponse = self.send_req_inner(req, should_redirect).await?;
		for _ in 0..self.redirect_limit {
			match current_resp {
				EpoxyResponse::Success(_) => break,
				EpoxyResponse::Redirect((_, req)) => {
					redirected = true;
					current_url = req.uri().clone();
					current_resp = self.send_req_inner(req, should_redirect).await?
				}
			}
		}

		match current_resp {
			EpoxyResponse::Success(resp) => Ok((resp, current_url, redirected)),
			EpoxyResponse::Redirect((resp, _)) => Ok((resp, current_url, redirected)),
		}
	}

	pub async fn fetch(
		&self,
		url: String,
		options: Object,
	) -> Result<web_sys::Response, EpoxyError> {
		let url: Uri = url.try_into()?;
		// only valid `Scheme`s are HTTP and HTTPS, which are the ones we support
		url.scheme().ok_or(EpoxyError::InvalidUrlScheme)?;

		let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
		let port_str = url
			.port_u16()
			.map(|x| format!(":{}", x))
			.unwrap_or_default();

		let request_method = object_get(&options, "method")
			.as_string()
			.unwrap_or_else(|| "GET".to_string());
		let request_method: Method = Method::from_str(&request_method)?;

		let request_redirect = !matches!(
			object_get(&options, "redirect")
				.as_string()
				.unwrap_or_default()
				.as_str(),
			"error" | "manual"
		);

		let mut body_content_type: Option<String> = None;
		let body = match object_truthy(object_get(&options, "body")) {
			Some(buf) => {
				let (body, content_type) = convert_body(buf)
					.await
					.map_err(|_| EpoxyError::InvalidRequestBody)?;
				body_content_type = content_type;
				Bytes::from(body.to_vec())
			}
			None => Bytes::new(),
		};

		let headers = object_truthy(object_get(&options, "headers")).and_then(|val| {
			if web_sys::Headers::instanceof(&val) {
				Some(entries_of_object(&from_entries(&val).ok()?))
			} else if val.is_truthy() {
				Some(entries_of_object(&Object::from(val)))
			} else {
				None
			}
		});

		let mut request_builder = Request::builder()
			.uri(url.clone())
			.method(request_method.clone());

		// Generic InvalidRequest because this only returns None if the builder has some error
		// which we don't know
		let headers_map = request_builder
			.headers_mut()
			.ok_or(EpoxyError::InvalidRequest)?;

		cfg_if! {
			if #[cfg(feature = "full")] {
				headers_map.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));
			} else {
				headers_map.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
			}
		}
		headers_map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
		headers_map.insert(USER_AGENT, HeaderValue::from_str(&self.user_agent)?);
		headers_map.insert(
			HOST,
			HeaderValue::from_str(&format!("{}{}", host, port_str))?,
		);

		if let Some(content_type) = body_content_type {
			headers_map.insert(CONTENT_TYPE, HeaderValue::from_str(&content_type)?);
		}

		if let Some(headers) = headers {
			for hdr in headers {
				headers_map.insert(
					HeaderName::from_str(&hdr[0])?,
					HeaderValue::from_str(&hdr[1])?,
				);
			}
		}

		if matches!(request_method, Method::POST | Method::PUT | Method::PATCH) && body.is_empty() {
			headers_map.insert(CONTENT_LENGTH, 0.into());
		}

		let (mut response, response_uri, redirected) = self
			.send_req(request_builder.body(HttpBody::new(body))?, request_redirect)
			.await?;

		if self.certs_tampered {
			response
				.headers_mut()
				.insert("X-Epoxy-CertsTampered", HeaderValue::from_static("true"));
		}

		let response_headers: Array = response
			.headers()
			.iter()
			.filter_map(|val| {
				Some(Array::of2(
					&val.0.as_str().into(),
					&val.1.to_str().ok()?.into(),
				))
			})
			.collect();
		let response_headers = from_entries(&response_headers)
			.map_err(|_| EpoxyError::ResponseHeadersFromEntriesFailed)?;

		let response_headers_raw = response.headers().clone();

		let response_builder = ResponseInit::new();
		response_builder.set_headers(&response_headers);
		response_builder.set_status(response.status().as_u16());
		response_builder.set_status_text(response.status().canonical_reason().unwrap_or_default());

		cfg_if! {
			if #[cfg(feature = "full")] {
				let response_stream = if !is_null_body(response.status().as_u16()) {
					let compression = match response
						.headers()
						.get("Content-Encoding")
						.and_then(|val| val.to_str().ok())
						.unwrap_or_default()
					{
						"gzip" => Some(EpoxyCompression::Gzip),
						"br" => Some(EpoxyCompression::Brotli),
						_ => None,
					};

					let response_body = IncomingBody::new(response.into_body()).into_async_read();
					let decompressed_body = match compression {
						Some(alg) => match alg {
							EpoxyCompression::Gzip => {
								Either::Left(Either::Left(async_comp::GzipDecoder::new(response_body)))
							}
							EpoxyCompression::Brotli => {
								Either::Left(Either::Right(async_comp::BrotliDecoder::new(response_body)))
							}
						},
						None => Either::Right(response_body),
					};
					Some(asyncread_to_readablestream(Box::pin(decompressed_body), self.buffer_size))
				} else {
					None
				};
			} else {
				let response_stream = if !is_null_body(response.status().as_u16()) {
					let response_body = IncomingBody::new(response.into_body()).into_async_read();
					Some(asyncread_to_readablestream(Box::pin(response_body)))
				} else {
					None
				};
			}
		}

		let resp = web_sys::Response::new_with_opt_readable_stream_and_init(
			response_stream.as_ref(),
			&response_builder,
		)
		.map_err(|_| EpoxyError::ResponseNewFailed)?;

		utils::define_property(&resp, "url", response_uri.to_string().into());
		utils::define_property(&resp, "redirected", redirected.into());

		let raw_headers = Object::new();
		for (k, v) in response_headers_raw.iter() {
			let k = k.as_str();
			let v: JsValue = v.to_str()?.to_string().into();
			let jv = object_get(&raw_headers, k);
			if jv.is_array() {
				let arr = Array::from(&jv);
				arr.push(&v);
				object_set(&raw_headers, k, arr.into());
			} else if jv.is_truthy() {
				object_set(&raw_headers, k, Array::of2(&jv, &v).into());
			} else {
				object_set(&raw_headers, k, v);
			}
		}
		utils::define_property(&resp, "rawHeaders", raw_headers.into());

		Ok(resp)
	}
}
