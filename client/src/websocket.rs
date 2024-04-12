use crate::*;

use base64::{engine::general_purpose::STANDARD, Engine};
use fastwebsockets::{
    CloseCode, FragmentCollectorRead, Frame, OpCode, Payload, Role, WebSocket, WebSocketWrite,
};
use futures_util::lock::Mutex;
use http_body_util::Full;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    StatusCode,
};
use std::str::from_utf8;
use tokio::io::WriteHalf;

#[wasm_bindgen(inspectable)]
pub struct EpxWebSocket {
    tx: Arc<Mutex<WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>>>,
    onerror: Function,
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub url: String,
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub protocols: Vec<String>,
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub origin: String,
}

#[wasm_bindgen]
impl EpxWebSocket {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<EpxWebSocket, JsError> {
        Err(jerr!("Use EpoxyClient.connect_ws() instead."))
    }

    // shut up
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        tcp: &EpoxyClient,
        onopen: Function,
        onclose: Function,
        onerror: Function,
        onmessage: Function,
        url: String,
        protocols: Vec<String>,
        origin: String,
    ) -> Result<EpxWebSocket, JsError> {
        let onerr = onerror.clone();
        let ret: Result<EpxWebSocket, JsError> = async move {
            let url = Uri::try_from(url).replace_err("Failed to parse URL")?;
            let host = url.host().replace_err("URL must have a host")?;

            let mut rand: [u8; 16] = [0; 16];
            getrandom::getrandom(&mut rand)?;
            let key = STANDARD.encode(rand);

            let mut builder = Request::builder()
                .method("GET")
                .uri(url.clone())
                .header("Host", host)
                .header("Origin", origin.clone())
                .header(UPGRADE, "websocket")
                .header(CONNECTION, "upgrade")
                .header("Sec-WebSocket-Key", key)
                .header("Sec-WebSocket-Version", "13");

            if !protocols.is_empty() {
                builder = builder.header("Sec-WebSocket-Protocol", protocols.join(", "));
            }

            let req = builder.body(Full::<Bytes>::new(Bytes::new()))?;

            let mut response = tcp.hyper_client.request(req).await?;
            verify(&response)?;

            let ws = WebSocket::after_handshake(
                TokioIo::new(hyper::upgrade::on(&mut response).await?),
                Role::Client,
            );

            let (rx, tx) = ws.split(tokio::io::split);

            let mut rx = FragmentCollectorRead::new(rx);
            let tx = Arc::new(Mutex::new(tx));
            let tx_cloned = tx.clone();

            wasm_bindgen_futures::spawn_local(async move {
                while let Ok(frame) = rx
                    .read_frame(&mut |arg| async { tx_cloned.lock().await.write_frame(arg).await })
                    .await
                {
                    match frame.opcode {
                        OpCode::Text => {
                            if let Ok(str) = from_utf8(&frame.payload) {
                                let _ = onmessage.call1(&JsValue::null(), &jval!(str));
                            }
                        }
                        OpCode::Binary => {
                            let _ = onmessage.call1(
                                &JsValue::null(),
                                &jval!(Uint8Array::from(frame.payload.to_vec().as_slice())),
                            );
                        }
                        OpCode::Close => {
                            let _ = onclose.call0(&JsValue::null());
                            break;
                        }
                        // ping/pong/continue
                        _ => {}
                    }
                }
            });

            onopen
                .call0(&Object::default())
                .replace_err("Failed to call onopen")?;

            Ok(Self {
                tx,
                onerror,
                origin,
                protocols,
                url: url.to_string(),
            })
        }
        .await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(ret.clone()));
            Err(ret)
        } else {
            ret
        }
    }

    #[wasm_bindgen]
    pub async fn send_text(&self, payload: String) -> Result<(), JsError> {
        let onerr = self.onerror.clone();
        let ret = self
            .tx
            .lock()
            .await
            .write_frame(Frame::text(Payload::Owned(payload.as_bytes().to_vec())))
            .await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(ret.to_string()));
            Err(ret.into())
        } else {
            Ok(ret?)
        }
    }

    #[wasm_bindgen]
    pub async fn send_binary(&self, payload: Uint8Array) -> Result<(), JsError> {
        let onerr = self.onerror.clone();
        let ret = self
            .tx
            .lock()
            .await
            .write_frame(Frame::binary(Payload::Owned(payload.to_vec())))
            .await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(ret.to_string()));
            Err(ret.into())
        } else {
            Ok(ret?)
        }
    }

    #[wasm_bindgen]
    pub async fn close(&self) -> Result<(), JsError> {
        self.tx
            .lock()
            .await
            .write_frame(Frame::close(CloseCode::Normal.into(), b""))
            .await?;
        Ok(())
    }
}

// https://github.com/snapview/tungstenite-rs/blob/314feea3055a93e585882fb769854a912a7e6dae/src/handshake/client.rs#L189
fn verify(response: &Response<Incoming>) -> Result<(), JsError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(jerr!("epoxy ws connect: Invalid status code"));
    }

    let headers = response.headers();

    if !headers
        .get("Upgrade")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(jerr!("epoxy ws connect: Invalid upgrade header"));
    }

    if !headers
        .get("Connection")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("Upgrade"))
        .unwrap_or(false)
    {
        return Err(jerr!("epoxy ws connect: Invalid upgrade header"));
    }

    Ok(())
}
