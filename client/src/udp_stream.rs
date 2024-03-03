use crate::*;

use futures_util::{stream::SplitSink, SinkExt};
use js_sys::Function;

#[wasm_bindgen(inspectable)]
pub struct EpxUdpStream {
    tx: SplitSink<MuxStreamIo, Vec<u8>>,
    onerror: Function,
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub url: String,
}

#[wasm_bindgen]
impl EpxUdpStream {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<EpxUdpStream, JsError> {
        Err(jerr!("Use EpoxyClient.connect_udp() instead."))
    }

    pub async fn connect(
        tcp: &EpoxyClient,
        onopen: Function,
        onclose: Function,
        onerror: Function,
        onmessage: Function,
        url: String,
    ) -> Result<EpxUdpStream, JsError> {
        let onerr = onerror.clone();
        let ret: Result<EpxUdpStream, JsError> = async move {
            let url = Uri::try_from(url).replace_err("Failed to parse URL")?;
            let url_host = url.host().replace_err("URL must have a host")?;
            let url_port = url.port().replace_err("URL must have a port")?.into();

            let io = tcp
                .mux
                .client_new_stream(StreamType::Udp, url_host.to_string(), url_port)
                .await
                .replace_err("Failed to open multiplexor channel")?
                .into_io();
            let (tx, mut rx) = io.split();

            wasm_bindgen_futures::spawn_local(async move {
                while let Some(Ok(data)) = rx.next().await {
                    let _ = onmessage.call1(
                        &JsValue::null(),
                        &jval!(Uint8Array::from(data.to_vec().as_slice())),
                    );
                }
                let _ = onclose.call0(&JsValue::null());
            });

            onopen
                .call0(&Object::default())
                .replace_err("Failed to call onopen")?;

            Ok(Self {
                tx,
                onerror,
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
    pub async fn send(&mut self, payload: Uint8Array) -> Result<(), JsError> {
        let onerr = self.onerror.clone();
        let ret = self.tx.send(payload.to_vec()).await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(format!("{}", ret)));
            Err(ret.into())
        } else {
            Ok(ret?)
        }
    }

    #[wasm_bindgen]
    pub async fn close(&mut self) -> Result<(), JsError> {
        self.tx.close().await?;
        Ok(())
    }
}
