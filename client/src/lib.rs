#![feature(let_chains, impl_trait_in_assoc_type)]
#[macro_use]
mod utils;
mod tls_stream;
mod tokioio;
mod udp_stream;
mod websocket;
mod wrappers;

use tls_stream::EpxTlsStream;
use tokioio::TokioIo;
use udp_stream::EpxUdpStream;
pub use utils::{Boolinator, ReplaceErr, UriExt};
use websocket::EpxWebSocket;
use wrappers::{IncomingBody, ServiceWrapper, TlsWispService, WebSocketWrapper};

use std::sync::Arc;

use async_compression::tokio::bufread as async_comp;
use async_io_stream::IoStream;
use bytes::Bytes;
use futures_util::StreamExt;
use http::{uri, HeaderName, HeaderValue, Request, Response};
use hyper::{body::Incoming, Uri};
use hyper_util_wasm::client::legacy::Client;
use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use rustls::pki_types::TrustAnchor;
use tokio::sync::RwLock;
use tokio_rustls::{client::TlsStream, rustls, rustls::RootCertStore, TlsConnector};
use tokio_util::{
    either::Either,
    io::{ReaderStream, StreamReader},
};
use wasm_bindgen::{intern, prelude::*};
use wisp_mux::{ClientMux, MuxStreamIo, StreamType};

type HttpBody = http_body_util::Full<Bytes>;

#[derive(Debug)]
enum EpxResponse {
    Success(Response<Incoming>),
    Redirect((Response<Incoming>, http::Request<HttpBody>)),
}

enum EpxCompression {
    Brotli,
    Gzip,
}

type EpxIoUnencryptedStream = IoStream<MuxStreamIo, Vec<u8>>;
type EpxIoTlsStream = TlsStream<EpxIoUnencryptedStream>;
type EpxIoStream = Either<EpxIoTlsStream, EpxIoUnencryptedStream>;

#[wasm_bindgen(start)]
fn init() {
    console_error_panic_hook::set_once();
    // utils.rs
    intern("value");
    intern("writable");
    intern("POST");

    // main.rs
    intern("method");
    intern("redirect");
    intern("body");
    intern("headers");
    intern("url");
    intern("redirected");
    intern("rawHeaders");
    intern("Content-Type");
}

fn cert_to_jval(cert: &TrustAnchor) -> Result<JsValue, JsValue> {
    let val = Object::new();
    Reflect::set(
        &val,
        &jval!("subject"),
        &Uint8Array::from(cert.subject.as_ref()),
    )?;
    Reflect::set(
        &val,
        &jval!("subject_public_key_info"),
        &Uint8Array::from(cert.subject_public_key_info.as_ref()),
    )?;
    Reflect::set(
        &val,
        &jval!("name_constraints"),
        &jval!(cert
            .name_constraints
            .as_ref()
            .map(|x| Uint8Array::from(x.as_ref()))),
    )?;
    Ok(val.into())
}

#[wasm_bindgen]
pub fn certs() -> Result<JsValue, JsValue> {
    Ok(webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(cert_to_jval)
        .collect::<Result<Array, JsValue>>()?
        .into())
}

#[wasm_bindgen(inspectable)]
pub struct EpoxyClient {
    rustls_config: Arc<rustls::ClientConfig>,
    mux: Arc<RwLock<ClientMux>>,
    hyper_client: Client<TlsWispService, HttpBody>,
    #[wasm_bindgen(getter_with_clone)]
    pub useragent: String,
    #[wasm_bindgen(js_name = "redirectLimit")]
    pub redirect_limit: usize,
}

#[wasm_bindgen]
impl EpoxyClient {
    #[wasm_bindgen(constructor)]
    pub async fn new(
        ws_url: String,
        useragent: String,
        redirect_limit: usize,
    ) -> Result<EpoxyClient, JsError> {
        let ws_uri = ws_url
            .parse::<uri::Uri>()
            .replace_err("Failed to parse websocket url")?;

        let ws_uri_scheme = ws_uri
            .scheme_str()
            .replace_err("Websocket URL must have a scheme")?;
        if ws_uri_scheme != "ws" && ws_uri_scheme != "wss" {
            return Err(JsError::new("Scheme must be either `ws` or `wss`"));
        }

        let (mux, fut) = utils::make_mux(&ws_url).await?;
        let mux = Arc::new(RwLock::new(mux));
        utils::spawn_mux_fut(mux.clone(), fut, ws_url.clone());

        let mut certstore = RootCertStore::empty();
        certstore.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let rustls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(certstore)
                .with_no_client_auth(),
        );

        Ok(EpoxyClient {
            mux: mux.clone(),
            hyper_client: Client::builder(utils::WasmExecutor {})
                .http09_responses(true)
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(TlsWispService {
                    rustls_config: rustls_config.clone(),
                    service: ServiceWrapper(mux, ws_url),
                }),
            rustls_config,
            useragent,
            redirect_limit,
        })
    }

    async fn get_tls_io(&self, url_host: &str, url_port: u16) -> Result<EpxIoTlsStream, JsError> {
        let channel = self
            .mux
            .write()
            .await
            .client_new_stream(StreamType::Tcp, url_host.to_string(), url_port)
            .await
            .replace_err("Failed to create multiplexor channel")?
            .into_io()
            .into_asyncrw();
        let connector = TlsConnector::from(self.rustls_config.clone());
        let io = connector
            .connect(
                url_host
                    .to_string()
                    .try_into()
                    .replace_err("Failed to parse URL (rustls)")?,
                channel,
            )
            .await
            .replace_err("Failed to perform TLS handshake")?;
        Ok(io)
    }

    async fn send_req_inner(
        &self,
        req: http::Request<HttpBody>,
        should_redirect: bool,
    ) -> Result<EpxResponse, JsError> {
        let new_req = if should_redirect {
            Some(req.clone())
        } else {
            None
        };

        let res = self
            .hyper_client
            .request(req)
            .await
            .replace_err("Failed to send request");
        match res {
            Ok(res) => {
                if utils::is_redirect(res.status().as_u16())
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
                    Ok(EpxResponse::Redirect((res, new_req)))
                } else {
                    Ok(EpxResponse::Success(res))
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn send_req(
        &self,
        req: http::Request<HttpBody>,
        should_redirect: bool,
    ) -> Result<(hyper::Response<Incoming>, Uri, bool), JsError> {
        let mut redirected = false;
        let mut current_url = req.uri().clone();
        let mut current_resp: EpxResponse = self.send_req_inner(req, should_redirect).await?;
        for _ in 0..self.redirect_limit {
            match current_resp {
                EpxResponse::Success(_) => break,
                EpxResponse::Redirect((_, req)) => {
                    redirected = true;
                    current_url = req.uri().clone();
                    current_resp = self.send_req_inner(req, should_redirect).await?
                }
            }
        }

        match current_resp {
            EpxResponse::Success(resp) => Ok((resp, current_url, redirected)),
            EpxResponse::Redirect((resp, _)) => Ok((resp, current_url, redirected)),
        }
    }

    // shut up
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_ws(
        &self,
        onopen: Function,
        onclose: Function,
        onerror: Function,
        onmessage: Function,
        url: String,
        protocols: Vec<String>,
        origin: String,
    ) -> Result<EpxWebSocket, JsError> {
        EpxWebSocket::connect(
            self, onopen, onclose, onerror, onmessage, url, protocols, origin,
        )
        .await
    }

    pub async fn connect_tls(
        &self,
        onopen: Function,
        onclose: Function,
        onerror: Function,
        onmessage: Function,
        url: String,
    ) -> Result<EpxTlsStream, JsError> {
        EpxTlsStream::connect(self, onopen, onclose, onerror, onmessage, url).await
    }

    pub async fn connect_udp(
        &self,
        onopen: Function,
        onclose: Function,
        onerror: Function,
        onmessage: Function,
        url: String,
    ) -> Result<EpxUdpStream, JsError> {
        EpxUdpStream::connect(self, onopen, onclose, onerror, onmessage, url).await
    }

    pub async fn fetch(&self, url: String, options: Object) -> Result<web_sys::Response, JsError> {
        let uri = url.parse::<uri::Uri>().replace_err("Failed to parse URL")?;
        let uri_scheme = uri.scheme().replace_err("URL must have a scheme")?;
        if *uri_scheme != uri::Scheme::HTTP && *uri_scheme != uri::Scheme::HTTPS {
            return Err(jerr!("Scheme must be either `http` or `https`"));
        }
        let uri_host = uri.host().replace_err("URL must have a host")?;

        let req_method_string: String = match Reflect::get(&options, &jval!("method")) {
            Ok(val) => val.as_string().unwrap_or("GET".to_string()),
            Err(_) => "GET".to_string(),
        };
        let req_method: http::Method = http::Method::try_from(req_method_string.as_str())
            .replace_err("Invalid http method")?;

        let req_should_redirect = match Reflect::get(&options, &jval!("redirect")) {
            Ok(val) => !matches!(
                val.as_string().unwrap_or_default().as_str(),
                "error" | "manual"
            ),
            Err(_) => true,
        };

        let mut body_content_type: Option<String> = None;
        let body_jsvalue: Option<JsValue> = Reflect::get(&options, &jval!("body")).ok();
        let body_bytes: Bytes = match body_jsvalue {
            Some(buf) => {
                let (body, req) = utils::jval_to_u8_array_req(buf)
                    .await
                    .replace_err("Invalid body")?;
                body_content_type = req.headers().get("Content-Type").ok().flatten();
                Bytes::from(body.to_vec())
            }
            None => Bytes::new(),
        };

        let headers = Reflect::get(&options, &jval!("headers"))
            .map(|val| {
                if web_sys::Headers::instanceof(&val) {
                    Some(utils::entries_of_object(&Object::from_entries(&val).ok()?))
                } else if val.is_truthy() {
                    Some(utils::entries_of_object(&Object::from(val)))
                } else {
                    None
                }
            })
            .unwrap_or(None);

        let mut builder = Request::builder().uri(uri.clone()).method(req_method);

        let headers_map = builder.headers_mut().replace_err("Failed to get headers")?;
        headers_map.insert("Accept-Encoding", HeaderValue::from_static("gzip, br"));
        headers_map.insert("Connection", HeaderValue::from_static("keep-alive"));
        headers_map.insert("User-Agent", HeaderValue::from_str(&self.useragent)?);
        headers_map.insert("Host", HeaderValue::from_str(uri_host)?);
        if body_bytes.is_empty() {
            headers_map.insert("Content-Length", HeaderValue::from_static("0"));
        }
        if let Some(content_type) = body_content_type {
            headers_map.insert("Content-Type", HeaderValue::from_str(&content_type)?);
        }

        if let Some(headers) = headers {
            for hdr in headers {
                headers_map.insert(
                    HeaderName::from_bytes(hdr[0].as_bytes())
                        .replace_err("Failed to get hdr name")?,
                    HeaderValue::from_bytes(hdr[1].as_bytes())
                        .replace_err("Failed to get hdr value")?,
                );
            }
        }

        let request = builder
            .body(HttpBody::new(body_bytes))
            .replace_err("Failed to make request")?;

        let (resp, resp_uri, req_redirected) = self.send_req(request, req_should_redirect).await?;

        let resp_headers_raw = resp.headers().clone();

        let resp_headers_jsarray = resp
            .headers()
            .iter()
            .filter_map(|val| {
                Some(Array::of2(
                    &jval!(val.0.as_str()),
                    &jval!(val.1.to_str().ok()?),
                ))
            })
            .collect::<Array>();

        let resp_headers = Object::from_entries(&resp_headers_jsarray)
            .replace_err("Failed to create response headers object")?;

        let mut respinit = web_sys::ResponseInit::new();
        respinit
            .headers(&resp_headers)
            .status(resp.status().as_u16())
            .status_text(resp.status().canonical_reason().unwrap_or_default());

        let stream = if !utils::is_null_body(resp.status().as_u16()) {
            let compression = match resp
                .headers()
                .get("Content-Encoding")
                .and_then(|val| val.to_str().ok())
                .unwrap_or_default()
            {
                "gzip" => Some(EpxCompression::Gzip),
                "br" => Some(EpxCompression::Brotli),
                _ => None,
            };

            let incoming_body = IncomingBody::new(resp.into_body());

            let decompressed_body = match compression {
                Some(alg) => match alg {
                    EpxCompression::Gzip => Either::Left(Either::Left(ReaderStream::new(
                        async_comp::GzipDecoder::new(StreamReader::new(incoming_body)),
                    ))),
                    EpxCompression::Brotli => Either::Left(Either::Right(ReaderStream::new(
                        async_comp::BrotliDecoder::new(StreamReader::new(incoming_body)),
                    ))),
                },
                None => Either::Right(incoming_body),
            };
            Some(
                wasm_streams::ReadableStream::from_stream(decompressed_body.map(|x| {
                    Ok(Uint8Array::from(
                        x.replace_err_jv("Failed to get frame from response")?
                            .as_ref(),
                    )
                    .into())
                }))
                .into_raw(),
            )
        } else {
            None
        };

        let resp =
            web_sys::Response::new_with_opt_readable_stream_and_init(stream.as_ref(), &respinit)
                .replace_err("Failed to make response")?;

        Object::define_property(
            &resp,
            &jval!("url"),
            &utils::define_property_obj(jval!(resp_uri.to_string()), false)
                .replace_err("Failed to make define_property object for url")?,
        );

        Object::define_property(
            &resp,
            &jval!("redirected"),
            &utils::define_property_obj(jval!(req_redirected), false)
                .replace_err("Failed to make define_property object for redirected")?,
        );

        let raw_headers = Object::new();
        for (k, v) in resp_headers_raw.iter() {
            let k = jval!(k.to_string());
            let v = jval!(v.to_str()?.to_string());
            if let Ok(jv) = Reflect::get(&raw_headers, &k) {
                if jv.is_array() {
                    let arr = Array::from(&jv);

                    arr.push(&v);
                    Reflect::set(&raw_headers, &k, &arr).flatten("Failed to set rawHeader")?;
                } else if jv.is_truthy() {
                    Reflect::set(&raw_headers, &k, &Array::of2(&jv, &v))
                        .flatten("Failed to set rawHeader")?;
                } else {
                    Reflect::set(&raw_headers, &k, &v).flatten("Failed to set rawHeader")?;
                }
            }
        }
        Object::define_property(
            &resp,
            &jval!("rawHeaders"),
            &utils::define_property_obj(jval!(&raw_headers), false)
                .replace_err("Failed to make define_property object for rawHeaders")?,
        );

        Ok(resp)
    }
}
