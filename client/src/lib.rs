#[macro_use]
mod utils;
mod tokioio;
mod wsstreamwrapper;

use tokioio::TokioIo;
use wsstreamwrapper::WsStreamWrapper;

use std::sync::Arc;

use bytes::Bytes;
use http::{uri, Request};
use hyper::{body::Incoming, client::conn as hyper_conn};
use js_sys::Object;
use penguin_mux_wasm::{Multiplexor, MuxStream, Role};
use tokio_rustls::{client::TlsStream, rustls, rustls::RootCertStore, TlsConnector};
use wasm_bindgen::prelude::*;

type MuxIo = TokioIo<MuxStream<WsStreamWrapper>>;
type MuxRustlsIo = TokioIo<TlsStream<MuxStream<WsStreamWrapper>>>;
type HttpBody = http_body_util::Full<Bytes>;

#[wasm_bindgen(start)]
async fn start() {
    utils::set_panic_hook();
}

#[wasm_bindgen]
pub struct WsTcpWorker {
    rustls_config: Arc<rustls::ClientConfig>,
    mux: Multiplexor<WsStreamWrapper>,
}

#[wasm_bindgen]
impl WsTcpWorker {
    #[wasm_bindgen(constructor)]
    pub async fn new(ws_url: String) -> Result<WsTcpWorker, JsValue> {
        let ws_uri = ws_url
            .parse::<uri::Uri>()
            .expect_throw("Failed to parse websocket URL");
        let ws_uri_scheme = ws_uri
            .scheme_str()
            .expect_throw("Websocket URL must have a scheme");
        if ws_uri_scheme != "ws" && ws_uri_scheme != "wss" {
            return Err("Scheme must be either `ws` or `wss`".into());
        }

        debug!("connecting to ws {:?}", ws_url);
        let (ws, wsmeta) = WsStreamWrapper::connect(ws_url, None)
            .await
            .expect_throw("Failed to connect to websocket");
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

        Ok(WsTcpWorker { mux, rustls_config })
    }

    pub async fn fetch(&self, url: String, options: Object) -> Result<(), JsValue> {
        let uri = url.parse::<uri::Uri>().expect_throw("Failed to parse URL");
        let uri_scheme = uri.scheme().expect_throw("URL must have a scheme");
        if *uri_scheme != uri::Scheme::HTTP && *uri_scheme != uri::Scheme::HTTPS {
            return Err("Scheme must be either `http` or `https`".into());
        }
        let uri_host = uri.host().expect_throw("URL must have a host");
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
                return Err("Failed to coerce port from scheme".into());
            }
        };

        let channel = self
            .mux
            .client_new_stream_channel(uri_host.as_bytes(), uri_port)
            .await
            .expect_throw("Failed to create multiplexor channel");

        let request = Request::builder()
            .header("Host", uri_host)
            .header("Connection", "close")
            .method("GET")
            .body(HttpBody::new(Bytes::new()))
            .expect_throw("Failed to create request");

        let resp: hyper::Response<Incoming>;

        if *uri_scheme == uri::Scheme::HTTPS {
            let cloned_uri = uri_host.to_string().clone();
            let connector = TlsConnector::from(self.rustls_config.clone());
            let io = connector
                .connect(
                    cloned_uri
                        .try_into()
                        .expect_throw("Failed to parse URL (rustls)"),
                    channel,
                )
                .await
                .expect_throw("Failed to perform TLS handshake");
            let io = TokioIo::new(io);
            let (mut req_sender, conn) = hyper_conn::http1::handshake::<MuxRustlsIo, HttpBody>(io)
                .await
                .expect_throw("Failed to connect to host");

            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = conn.await {
                    error!("wstcp: error in muxed hyper connection! {:?}", e);
                }
            });

            debug!("sending req tls");
            resp = req_sender.send_request(request).await.expect_throw("Failed to send request");
            debug!("recieved resp");
        } else {
            let io = TokioIo::new(channel);
            let (mut req_sender, conn) = hyper_conn::http1::handshake::<MuxIo, HttpBody>(io)
                .await
                .expect_throw("Failed to connect to host");

            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = conn.await {
                    error!("err in conn: {:?}", e);
                }
            });
            debug!("sending req");
            resp = req_sender.send_request(request).await.expect_throw("Failed to send request");
            debug!("recieved resp");
        }

        log!("{:?}", resp);

        Ok(())
    }
}
