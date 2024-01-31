use crate::*;

use base64::{engine::general_purpose::STANDARD, Engine};
use fastwebsockets::{
    CloseCode, FragmentCollectorRead, Frame, OpCode, Payload, Role, WebSocket, WebSocketWrite,
};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    StatusCode,
};
use js_sys::Function;
use std::str::from_utf8;
use tokio::io::WriteHalf;

#[wasm_bindgen]
pub struct EpxWebSocket {
    tx: WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>,
    onerror: Function,
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
        tcp: &mut EpoxyClient,
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

            let rand: [u8; 16] = rand::random();
            let key = STANDARD.encode(rand);

            let mut builder = Request::builder()
                .method("GET")
                .uri(url.clone())
                .header("Host", host)
                .header("Origin", origin)
                .header(UPGRADE, "websocket")
                .header(CONNECTION, "upgrade")
                .header("Sec-WebSocket-Key", key)
                .header("Sec-WebSocket-Version", "13");

            if !protocols.is_empty() {
                builder = builder.header("Sec-WebSocket-Protocol", protocols.join(", "));
            }

            let req = builder.body(Empty::<Bytes>::new())?;

            let stream = tcp.get_http_io(&url).await?;

            let (mut sender, conn) = Builder::new()
                .title_case_headers(true)
                .preserve_header_case(true)
                .handshake::<TokioIo<EpxStream>, Empty<Bytes>>(TokioIo::new(stream))
                .await?;

            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = conn.with_upgrades().await {
                    error!("epoxy: error in muxed hyper connection (ws)! {:?}", e);
                }
            });

            let mut response = sender.send_request(req).await?;
            verify(&response)?;

            let ws = WebSocket::after_handshake(
                TokioIo::new(hyper::upgrade::on(&mut response).await?),
                Role::Client,
            );

            let (rx, tx) = ws.split(tokio::io::split);

            let mut rx = FragmentCollectorRead::new(rx);

            wasm_bindgen_futures::spawn_local(async move {
                while let Ok(frame) = rx
                    .read_frame(&mut |arg| async move {
                        error!(
                            "wtf is an obligated write {:?}, {:?}, {:?}",
                            arg.fin, arg.opcode, arg.payload
                        );
                        Ok::<(), std::io::Error>(())
                    })
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
                        _ => panic!("unknown opcode {:?}", frame.opcode),
                    }
                }
            });

            onopen
                .call0(&Object::default())
                .replace_err("Failed to call onopen")?;

            Ok(Self { tx, onerror })
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
    pub async fn send(&mut self, payload: String) -> Result<(), JsError> {
        let onerr = self.onerror.clone();
        let ret = self
            .tx
            .write_frame(Frame::text(Payload::Owned(payload.as_bytes().to_vec())))
            .await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(format!("{}", ret)));
            Err(ret.into())
        } else {
            Ok(ret?)
        }
    }

    #[wasm_bindgen]
    pub async fn close(&mut self) -> Result<(), JsError> {
        self.tx
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
