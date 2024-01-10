#[macro_use]
mod utils;
mod tokioio;
mod wsstreamwrapper;

use tokioio::TokioIo;
use utils::ReplaceErr;
use wsstreamwrapper::WsStreamWrapper;

use std::sync::Arc;

use bytes::Bytes;
use http::{uri, HeaderName, HeaderValue, Request, Response};
use http_body_util::BodyExt;
use hyper::{body::Incoming, client::conn as hyper_conn};
use js_sys::{Object, Reflect, Uint8Array};
use penguin_mux_wasm::{Multiplexor, Role};
use tokio_rustls::{rustls, rustls::RootCertStore, TlsConnector};
use wasm_bindgen::prelude::*;
use web_sys::TextEncoder;

type HttpBody = http_body_util::Full<Bytes>;

async fn send_req<T>(req: http::Request<HttpBody>, io: T) -> Result<Response<Incoming>, JsError>
where
    T: hyper::rt::Read + hyper::rt::Write + std::marker::Unpin + 'static,
{
    let (mut req_sender, conn) = hyper_conn::http1::handshake::<T, HttpBody>(io)
        .await
        .replace_err("Failed to connect to host")?;

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = conn.await {
            error!("wstcp: error in muxed hyper connection! {:?}", e);
        }
    });

    debug!("sending req");
    req_sender
        .send_request(req)
        .await
        .replace_err("Failed to send request")
}

#[wasm_bindgen(start)]
async fn start() {
    utils::set_panic_hook();
}

#[wasm_bindgen]
pub struct WsTcpWorker {
    rustls_config: Arc<rustls::ClientConfig>,
    mux: Multiplexor<WsStreamWrapper>,
    useragent: String,
}

#[wasm_bindgen]
impl WsTcpWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(ws_url: String, useragent: String) -> Result<WsTcpWorker, JsError> {
        let ws_uri = ws_url
            .parse::<uri::Uri>()
            .replace_err("Failed to parse websocket url")?;

        let ws_uri_scheme = ws_uri
            .scheme_str()
            .replace_err("Websocket URL must have a scheme")?;
        if ws_uri_scheme != "ws" && ws_uri_scheme != "wss" {
            return Err(JsError::new("Scheme must be either `ws` or `wss`"));
        }

        debug!("connecting to ws {:?}", ws_url);
        let (ws, wsmeta) = WsStreamWrapper::connect(ws_url, None)
            .await
            .replace_err("Failed to connect to websocket")?;
        debug!("connected!");
        let mux = Multiplexor::new(ws, Role::Client, None, None);

        debug!("wsmeta ready state: {:?}", wsmeta.ready_state());

        let mut certstore = RootCertStore::empty();
        certstore.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let rustls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(certstore)
                .with_no_client_auth(),
        );

        Ok(WsTcpWorker {
            mux,
            rustls_config,
            useragent,
        })
    }

    pub async fn fetch(&self, url: String, options: Object) -> Result<(), JsError> {
        let uri = url.parse::<uri::Uri>().replace_err("Failed to parse URL")?;
        let uri_scheme = uri.scheme().replace_err("URL must have a scheme")?;
        if *uri_scheme != uri::Scheme::HTTP && *uri_scheme != uri::Scheme::HTTPS {
            return Err(nerr!("Scheme must be either `http` or `https`"));
        }
        let uri_host = uri.host().replace_err("URL must have a host")?;
        let uri_port = if let Some(port) = uri.port() {
            port.as_u16()
        } else {
            // can't use match, compiler error
            // error: to use a constant of type `Scheme` in a pattern, `Scheme` must be annotated with `#[derive(PartialEq, Eq)]`
            if *uri_scheme == uri::Scheme::HTTP {
                80
            } else if *uri_scheme == uri::Scheme::HTTPS {
                443
            } else {
                return Err(nerr!("Failed to coerce port from scheme"));
            }
        };

        let req_method_string: String = match Reflect::get(&options, &JsValue::from_str("method")) {
            Ok(val) => val.as_string().unwrap_or("GET".to_string()),
            Err(_) => "GET".to_string(),
        };
        debug!("method {:?}", req_method_string);
        let req_method: http::Method =
            http::Method::try_from(<String as AsRef<str>>::as_ref(&req_method_string))
                .replace_err("Invalid http method")?;

        let body_jsvalue: Option<JsValue> = Reflect::get(&options, &JsValue::from_str("body")).ok();
        let body = if let Some(val) = body_jsvalue {
            if val.is_string() {
                let str = val
                    .as_string()
                    .replace_err("Failed to get string from body")?;
                let encoder =
                    TextEncoder::new().replace_err("Failed to create TextEncoder for body")?;
                let encoded = encoder.encode_with_input(str.as_ref());
                Some(encoded)
            } else {
                Some(Uint8Array::new(&val).to_vec())
            }
        } else {
            None
        };

        let body_bytes: Bytes = match body {
            Some(vec) => Bytes::from(vec),
            None => Bytes::new(),
        };

        let headers: Option<Vec<Vec<String>>> =
            Reflect::get(&options, &JsValue::from_str("headers"))
                .map(|val| {
                    if val.is_truthy() {
                        Some(utils::entries_of_object(&Object::from(val)))
                    } else {
                        None
                    }
                })
                .unwrap_or(None);

        let mut builder = Request::builder().uri(uri.clone()).method(req_method);

        if let Some(headers) = headers {
            let headers_map = builder.headers_mut().replace_err("Failed to get headers")?;
            for hdr in headers {
                headers_map.insert(
                    HeaderName::from_bytes(hdr[0].as_bytes())
                        .replace_err("Failed to get hdr name")?,
                    HeaderValue::from_str(hdr[1].clone().as_ref())
                        .replace_err("Failed to get hdr value")?,
                );
            }
        }

        builder = builder
            .header("Host", uri_host)
            .header("Connection", "close")
            .header("User-Agent", self.useragent.clone());

        let request = builder
            .body(HttpBody::new(body_bytes))
            .replace_err("Failed to make request")?;

        let channel = self
            .mux
            .client_new_stream_channel(uri_host.as_bytes(), uri_port)
            .await
            .replace_err("Failed to create multiplexor channel")?;

        let mut resp: hyper::Response<Incoming>;

        if *uri_scheme == uri::Scheme::HTTPS {
            let cloned_uri = uri_host.to_string().clone();
            let connector = TlsConnector::from(self.rustls_config.clone());
            let io = connector
                .connect(
                    cloned_uri
                        .try_into()
                        .replace_err("Failed to parse URL (rustls)")?,
                    channel,
                )
                .await
                .replace_err("Failed to perform TLS handshake")?;
            resp = send_req(request, TokioIo::new(io)).await?;
        } else {
            resp = send_req(request, TokioIo::new(channel)).await?;
        }

        log!("{:?}", resp);
        let body = resp.body_mut().collect();
        let body_bytes = body.await.replace_err("Failed to get body")?.to_bytes();
        log!("{}", std::str::from_utf8(&body_bytes).replace_err("e")?);

        Ok(())
    }
}
