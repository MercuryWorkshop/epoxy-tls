#![feature(let_chains, impl_trait_in_assoc_type)]
use std::{str::FromStr, sync::Arc};

use async_compression::futures::bufread as async_comp;
use bytes::Bytes;
use futures_util::{future::Either, TryStreamExt};
use http::{
    header::{InvalidHeaderName, InvalidHeaderValue},
    method::InvalidMethod,
    uri::{InvalidUri, InvalidUriParts},
    HeaderName, HeaderValue, Method, Request, Response,
};
use hyper::{body::Incoming, Uri};
use hyper_util_wasm::client::legacy::Client;
use io_stream::{EpoxyIoStream, EpoxyUdpStream};
use js_sys::{Array, Function, Object, Reflect};
use stream_provider::{StreamProvider, StreamProviderService};
use thiserror::Error;
use utils::{
    convert_body, entries_of_object, is_null_body, is_redirect, object_get, object_set,
    IncomingBody, UriExt, WasmExecutor,
};
use wasm_bindgen::prelude::*;
use wasm_streams::ReadableStream;
use web_sys::ResponseInit;
use websocket::EpoxyWebSocket;
use wisp_mux::StreamType;

mod io_stream;
mod stream_provider;
mod tokioio;
mod utils;
mod websocket;
mod ws_wrapper;

type HttpBody = http_body_util::Full<Bytes>;

#[derive(Debug, Error)]
pub enum EpoxyError {
    #[error("Invalid DNS name: {0:?}")]
    InvalidDnsName(#[from] futures_rustls::rustls::pki_types::InvalidDnsNameError),
    #[error("Wisp: {0:?}")]
    Wisp(#[from] wisp_mux::WispError),
    #[error("IO: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("HTTP: {0:?}")]
    Http(#[from] http::Error),
    #[error("Hyper client: {0:?}")]
    HyperClient(#[from] hyper_util_wasm::client::legacy::Error),
    #[error("Hyper: {0:?}")]
    Hyper(#[from] hyper::Error),
    #[error("HTTP ToStr: {0:?}")]
    ToStr(#[from] http::header::ToStrError),
    #[error("Getrandom: {0:?}")]
    GetRandom(#[from] getrandom::Error),
    #[error("Fastwebsockets: {0:?}")]
    FastWebSockets(#[from] fastwebsockets::WebSocketError),

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
    #[error("Invalid websocket response status code")]
    WsInvalidStatusCode,
    #[error("Invalid websocket upgrade header")]
    WsInvalidUpgradeHeader,
    #[error("Invalid websocket connection header")]
    WsInvalidConnectionHeader,
    #[error("Invalid websocket payload")]
    WsInvalidPayload,
    #[error("Invalid payload")]
    InvalidPayload,

    #[error("Invalid certificate store")]
    InvalidCertStore,
    #[error("WebSocket failed to connect")]
    WebSocketConnectFailed,

    #[error("Failed to construct response headers object")]
    ResponseHeadersFromEntriesFailed,
    #[error("Failed to construct response object")]
    ResponseNewFailed,
    #[error("Failed to construct define_property object")]
    DefinePropertyObjFailed,
    #[error("Failed to set raw header item")]
    RawHeaderSetFailed,
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

#[derive(Debug)]
enum EpoxyResponse {
    Success(Response<Incoming>),
    Redirect((Response<Incoming>, http::Request<HttpBody>)),
}

enum EpoxyCompression {
    Brotli,
    Gzip,
}

#[wasm_bindgen]
pub struct EpoxyClientOptions {
    pub wisp_v2: bool,
    pub udp_extension_required: bool,
    #[wasm_bindgen(getter_with_clone)]
    pub websocket_protocols: Vec<String>,
    pub redirect_limit: usize,
    #[wasm_bindgen(getter_with_clone)]
    pub user_agent: String,
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
            wisp_v2: true,
            udp_extension_required: true,
            websocket_protocols: Vec::new(),
            redirect_limit: 10,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36".to_string(),
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

#[wasm_bindgen(inspectable)]
pub struct EpoxyClient {
    stream_provider: Arc<StreamProvider>,
    client: Client<StreamProviderService, HttpBody>,

    pub redirect_limit: usize,
    #[wasm_bindgen(getter_with_clone)]
    pub user_agent: String,
}

#[wasm_bindgen]
impl EpoxyClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        wisp_url: String,
        certs: Array,
        options: EpoxyClientOptions,
    ) -> Result<EpoxyClient, EpoxyError> {
        let wisp_url: Uri = wisp_url.try_into()?;
        if wisp_url.scheme_str() != Some("wss") && wisp_url.scheme_str() != Some("ws") {
            return Err(EpoxyError::InvalidUrlScheme);
        }

        let stream_provider = Arc::new(StreamProvider::new(wisp_url.to_string(), certs, &options)?);

        let service = StreamProviderService(stream_provider.clone());
        let client = Client::builder(WasmExecutor)
            .http09_responses(true)
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(service);

        Ok(Self {
            stream_provider,
            client,
            redirect_limit: options.redirect_limit,
            user_agent: options.user_agent,
        })
    }

    pub async fn replace_stream_provider(&self) -> Result<(), EpoxyError> {
        self.stream_provider.replace_client().await
    }

    pub async fn connect_websocket(
        &self,
        handlers: EpoxyHandlers,
        url: String,
        protocols: Vec<String>,
		headers: JsValue,
    ) -> Result<EpoxyWebSocket, EpoxyError> {
        EpoxyWebSocket::connect(self, handlers, url, protocols, headers, &self.user_agent).await
    }

    pub async fn connect_tcp(
        &self,
        handlers: EpoxyHandlers,
        url: String,
    ) -> Result<EpoxyIoStream, EpoxyError> {
        let url: Uri = url.try_into()?;
        let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
        let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
        match self
            .stream_provider
            .get_asyncread(StreamType::Tcp, host.to_string(), port)
            .await
        {
            Ok(stream) => Ok(EpoxyIoStream::connect(Either::Right(stream), handlers)),
            Err(err) => {
                let _ = handlers
                    .onerror
                    .call1(&JsValue::null(), &err.to_string().into());
                Err(err)
            }
        }
    }

    pub async fn connect_tls(
        &self,
        handlers: EpoxyHandlers,
        url: String,
    ) -> Result<EpoxyIoStream, EpoxyError> {
        let url: Uri = url.try_into()?;
        let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
        let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
        match self
            .stream_provider
            .get_tls_stream(host.to_string(), port)
            .await
        {
            Ok(stream) => Ok(EpoxyIoStream::connect(Either::Left(stream), handlers)),
            Err(err) => {
                let _ = handlers
                    .onerror
                    .call1(&JsValue::null(), &err.to_string().into());
                Err(err)
            }
        }
    }

    pub async fn connect_udp(
        &self,
        handlers: EpoxyHandlers,
        url: String,
    ) -> Result<EpoxyUdpStream, EpoxyError> {
        let url: Uri = url.try_into()?;
        let host = url.host().ok_or(EpoxyError::NoUrlHost)?;
        let port = url.port_u16().ok_or(EpoxyError::NoUrlPort)?;
        match self
            .stream_provider
            .get_stream(StreamType::Udp, host.to_string(), port)
            .await
        {
            Ok(stream) => Ok(EpoxyUdpStream::connect(stream, handlers)),
            Err(err) => {
                let _ = handlers
                    .onerror
                    .call1(&JsValue::null(), &err.to_string().into());
                Err(err)
            }
        }
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

        let request_method = object_get(&options, "method")
            .and_then(|x| x.as_string())
            .unwrap_or_else(|| "GET".to_string());
        let request_method: Method = Method::from_str(&request_method)?;

        let request_redirect = object_get(&options, "redirect")
            .map(|x| {
                !matches!(
                    x.as_string().unwrap_or_default().as_str(),
                    "error" | "manual"
                )
            })
            .unwrap_or(true);

        let mut body_content_type: Option<String> = None;
        let body = match object_get(&options, "body") {
            Some(buf) => {
                let (body, req) = convert_body(buf)
                    .await
                    .map_err(|_| EpoxyError::InvalidRequestBody)?;
                body_content_type = req.headers().get("Content-Type").ok().flatten();
                Bytes::from(body.to_vec())
            }
            None => Bytes::new(),
        };

        let headers = object_get(&options, "headers").and_then(|val| {
            if web_sys::Headers::instanceof(&val) {
                Some(entries_of_object(&Object::from_entries(&val).ok()?))
            } else if val.is_truthy() {
                Some(entries_of_object(&Object::from(val)))
            } else {
                None
            }
        });

        let mut request_builder = Request::builder().uri(url.clone()).method(request_method);

        // Generic InvalidRequest because this only returns None if the builder has some error
        // which we don't know
        let headers_map = request_builder
            .headers_mut()
            .ok_or(EpoxyError::InvalidRequest)?;

        headers_map.insert("Accept-Encoding", HeaderValue::from_static("identity"));
        headers_map.insert("Connection", HeaderValue::from_static("keep-alive"));
        headers_map.insert("User-Agent", HeaderValue::from_str(&self.user_agent)?);
        headers_map.insert("Host", HeaderValue::from_str(host)?);

        if body.is_empty() {
            headers_map.insert("Content-Length", HeaderValue::from_static("0"));
        }

        if let Some(content_type) = body_content_type {
            headers_map.insert("Content-Type", HeaderValue::from_str(&content_type)?);
        }

        if let Some(headers) = headers {
            for hdr in headers {
                headers_map.insert(
                    HeaderName::from_str(&hdr[0])?,
                    HeaderValue::from_str(&hdr[1])?,
                );
            }
        }

        let (response, response_uri, redirected) = self
            .send_req(request_builder.body(HttpBody::new(body))?, request_redirect)
            .await?;

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
        let response_headers = Object::from_entries(&response_headers)
            .map_err(|_| EpoxyError::ResponseHeadersFromEntriesFailed)?;

        let response_headers_raw = response.headers().clone();

        let mut response_builder = ResponseInit::new();
        response_builder
            .headers(&response_headers)
            .status(response.status().as_u16())
            .status_text(response.status().canonical_reason().unwrap_or_default());

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
            Some(ReadableStream::from_async_read(decompressed_body, 1024).into_raw())
        } else {
            None
        };

        let resp = web_sys::Response::new_with_opt_readable_stream_and_init(
            response_stream.as_ref(),
            &response_builder,
        )
        .map_err(|_| EpoxyError::ResponseNewFailed)?;

        Object::define_property(
            &resp,
            &"url".into(),
            &utils::define_property_obj(response_uri.to_string().into(), false)
                .map_err(|_| EpoxyError::DefinePropertyObjFailed)?,
        );

        Object::define_property(
            &resp,
            &"redirected".into(),
            &utils::define_property_obj(redirected.into(), false)
                .map_err(|_| EpoxyError::DefinePropertyObjFailed)?,
        );

        let raw_headers = Object::new();
        for (k, v) in response_headers_raw.iter() {
            let k: JsValue = k.to_string().into();
            let v: JsValue = v.to_str()?.to_string().into();
            if let Ok(jv) = Reflect::get(&raw_headers, &k) {
                if jv.is_array() {
                    let arr = Array::from(&jv);
                    arr.push(&v);
                    object_set(&raw_headers, &k, &arr)?;
                } else if jv.is_truthy() {
                    object_set(&raw_headers, &k, &Array::of2(&jv, &v))?;
                } else {
                    object_set(&raw_headers, &k, &v)?;
                }
            }
        }
        Object::define_property(
            &resp,
            &"rawHeaders".into(),
            &utils::define_property_obj(raw_headers.into(), false)
                .map_err(|_| EpoxyError::DefinePropertyObjFailed)?,
        );

        Ok(resp)
    }
}
