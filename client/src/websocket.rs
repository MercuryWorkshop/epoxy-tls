use std::{str::from_utf8, sync::Arc};

use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::Bytes;
use fastwebsockets::{
    CloseCode, FragmentCollectorRead, Frame, OpCode, Payload, Role, WebSocket, WebSocketWrite,
};
use futures_util::lock::Mutex;
use getrandom::getrandom;
use http::{
    header::{
        CONNECTION, HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    Method, Request, Response, StatusCode, Uri,
};
use hyper::{
    body::Incoming,
    upgrade::{self, Upgraded},
};
use js_sys::{ArrayBuffer, Function, Uint8Array};
use tokio::io::WriteHalf;
use wasm_bindgen::{prelude::*, JsError, JsValue};
use wasm_bindgen_futures::spawn_local;

use crate::{tokioio::TokioIo, EpoxyClient, EpoxyError, EpoxyHandlers, HttpBody};

#[wasm_bindgen]
pub struct EpoxyWebSocket {
    tx: Arc<Mutex<WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>>>,
    onerror: Function,
}

#[wasm_bindgen]
impl EpoxyWebSocket {
    pub(crate) async fn connect(
        client: &EpoxyClient,
        handlers: EpoxyHandlers,
        url: String,
        protocols: Vec<String>,
    ) -> Result<Self, EpoxyError> {
        let EpoxyHandlers {
            onopen,
            onclose,
            onerror,
            onmessage,
        } = handlers;
        let onerror_cloned = onerror.clone();
        let ret: Result<EpoxyWebSocket, EpoxyError> = async move {
            let url: Uri = url.try_into()?;
            let host = url.host().ok_or(EpoxyError::NoUrlHost)?;

            let mut rand = [0u8; 16];
            getrandom(&mut rand)?;
            let key = BASE64_STANDARD.encode(rand);

            let mut request = Request::builder()
                .method(Method::GET)
                .uri(url.clone())
                .header(HOST, host)
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket")
                .header(SEC_WEBSOCKET_KEY, key)
                .header(SEC_WEBSOCKET_VERSION, "13");

            if !protocols.is_empty() {
                request = request.header(SEC_WEBSOCKET_PROTOCOL, protocols.join(","));
            }

            let request = request.body(HttpBody::new(Bytes::new()))?;

            let mut response = client.client.request(request).await?;
            verify(&response)?;

            let websocket = WebSocket::after_handshake(
                TokioIo::new(upgrade::on(&mut response).await?),
                Role::Client,
            );

            let (rx, tx) = websocket.split(tokio::io::split);

            let mut rx = FragmentCollectorRead::new(rx);
            let tx = Arc::new(Mutex::new(tx));

            let read_tx = tx.clone();
            let onerror_cloned = onerror.clone();

            spawn_local(async move {
                loop {
                    match rx
                        .read_frame(&mut |arg| async {
                            read_tx.lock().await.write_frame(arg).await
                        })
                        .await
                    {
                        Ok(frame) => match frame.opcode {
                            OpCode::Text => {
                                if let Ok(str) = from_utf8(&frame.payload) {
                                    let _ = onmessage.call1(&JsValue::null(), &str.into());
                                }
                            }
                            OpCode::Binary => {
                                let _ = onmessage.call1(
                                    &JsValue::null(),
                                    &Uint8Array::from(frame.payload.to_vec().as_slice()).into(),
                                );
                            }
                            OpCode::Close => {
                                let _ = onclose.call0(&JsValue::null());
                                break;
                            }
                            // ping/pong/continue
                            _ => {}
                        },
                        Err(err) => {
                            let _ = onerror.call1(&JsValue::null(), &JsError::from(err).into());
                            break;
                        }
                    }
                }
                let _ = onclose.call0(&JsValue::null());
            });

            let _ = onopen.call0(&JsValue::null());

            Ok(Self {
                tx,
                onerror: onerror_cloned,
            })
        }
        .await;

        match ret {
            Ok(ok) => Ok(ok),
            Err(err) => {
                let _ = onerror_cloned.call1(&JsValue::null(), &err.to_string().into());
                Err(err)
            }
        }
    }

    pub async fn send(&self, payload: JsValue) -> Result<(), EpoxyError> {
        let ret = if let Some(str) = payload.as_string() {
            self.tx
                .lock()
                .await
                .write_frame(Frame::text(Payload::Owned(str.as_bytes().to_vec())))
                .await
                .map_err(EpoxyError::from)
        } else if let Ok(binary) = payload.dyn_into::<ArrayBuffer>() {
            self.tx
                .lock()
                .await
                .write_frame(Frame::binary(Payload::Owned(
                    Uint8Array::new(&binary).to_vec(),
                )))
                .await
                .map_err(EpoxyError::from)
        } else {
            Err(EpoxyError::WsInvalidPayload)
        };

        match ret {
            Ok(ok) => Ok(ok),
            Err(err) => {
                let _ = self
                    .onerror
                    .call1(&JsValue::null(), &err.to_string().into());
                Err(err)
            }
        }
    }

    pub async fn close(&self) -> Result<(), EpoxyError> {
        let ret = self
            .tx
            .lock()
            .await
            .write_frame(Frame::close(CloseCode::Normal.into(), b""))
            .await;
        match ret {
            Ok(ok) => Ok(ok),
            Err(err) => {
                let _ = self
                    .onerror
                    .call1(&JsValue::null(), &err.to_string().into());
                Err(err.into())
            }
        }
    }
}

// https://github.com/snapview/tungstenite-rs/blob/314feea3055a93e585882fb769854a912a7e6dae/src/handshake/client.rs#L189
fn verify(response: &Response<Incoming>) -> Result<(), EpoxyError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(EpoxyError::WsInvalidStatusCode);
    }

    let headers = response.headers();

    if !headers
        .get(UPGRADE)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(EpoxyError::WsInvalidUpgradeHeader);
    }

    if !headers
        .get(CONNECTION)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("Upgrade"))
        .unwrap_or(false)
    {
        return Err(EpoxyError::WsInvalidConnectionHeader);
    }

    Ok(())
}
