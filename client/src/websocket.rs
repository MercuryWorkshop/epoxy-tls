use crate::*;

use base64::{engine::general_purpose::STANDARD, Engine};
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketError};
use http_body_util::Empty;
use hyper::{
    client::conn::http1 as hyper_conn,
    header::{CONNECTION, UPGRADE},
    StatusCode,
};
use js_sys::Function;
use std::str::from_utf8;
use tokio::sync::{mpsc, oneshot};

enum EpxMsg {
    SendText(String, oneshot::Sender<Result<(), WebSocketError>>),
    Close,
}

#[wasm_bindgen]
pub struct EpxWebSocket {
    msg_sender: mpsc::Sender<EpxMsg>,
}

#[wasm_bindgen]
impl EpxWebSocket {
    #[wasm_bindgen(constructor)]
    pub async fn connect(
        onopen: Function,
        onclose: Function,
        onmessage: Function,
        tcp: &EpoxyClient,
        url: String,
        protocols: Vec<String>,
        origin: String,
    ) -> Result<EpxWebSocket, JsError> {
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

        let (mut sender, conn) =
            hyper_conn::handshake::<TokioIo<EpxStream>, Empty<Bytes>>(TokioIo::new(stream))
                .await?;

        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = conn.with_upgrades().await {
                error!("wstcp: error in muxed hyper connection (ws)! {:?}", e);
            }
        });

        let mut response = sender.send_request(req).await?;
        verify(&response)?;

        let mut ws = WebSocket::after_handshake(
            TokioIo::new(hyper::upgrade::on(&mut response).await?),
            Role::Client,
        );

        let (msg_sender, mut rx) = mpsc::channel(1);

        wasm_bindgen_futures::spawn_local(async move {
            loop {
                tokio::select! {
                    frame = ws.read_frame() => {
                        if let Ok(frame) = frame {
                            error!("hiii");
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
                    }
                    msg = rx.recv() => {
                        if let Some(msg) = msg {
                            match msg {
                                EpxMsg::SendText(payload, err) => {
                                    let _ = err.send(ws.write_frame(Frame::text(
                                        Payload::Owned(payload.as_bytes().to_vec()),
                                    ))
                                    .await);
                                }
                                EpxMsg::Close => break,
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            let _ = ws.write_frame(Frame::close(CloseCode::Normal.into(), b""))
                .await;
        });

        onopen
            .call0(&Object::default())
            .replace_err("Failed to call onopen")?;

        Ok(Self { msg_sender })
    }

    #[wasm_bindgen]
    pub async fn send(&mut self, payload: String) -> Result<(), JsError> {
        let (tx, rx) = oneshot::channel();
        self.msg_sender.send(EpxMsg::SendText(payload, tx)).await?;
        Ok(rx.await??)
    }

    #[wasm_bindgen]
    pub async fn close(&mut self) -> Result<(), JsError> {
        self.msg_sender.send(EpxMsg::Close).await?;
        Ok(())
    }
}

// https://github.com/snapview/tungstenite-rs/blob/314feea3055a93e585882fb769854a912a7e6dae/src/handshake/client.rs#L189
fn verify(response: &Response<Incoming>) -> Result<(), JsError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(jerr!("wstcpws connect: Invalid status code"));
    }

    let headers = response.headers();

    if !headers
        .get("Upgrade")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(jerr!("wstcpws connect: Invalid upgrade header"));
    }

    if !headers
        .get("Connection")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("Upgrade"))
        .unwrap_or(false)
    {
        return Err(jerr!("wstcpws connect: Invalid upgrade header"));
    }

    Ok(())
}
