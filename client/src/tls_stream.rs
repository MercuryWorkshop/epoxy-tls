use crate::*;

use js_sys::Function;
use tokio::io::{split, AsyncWriteExt, WriteHalf};
use tokio_util::io::ReaderStream;

#[wasm_bindgen(inspectable)]
pub struct EpxTlsStream {
    tx: WriteHalf<EpxIoTlsStream>,
    onerror: Function,
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub url: String,
}

#[wasm_bindgen]
impl EpxTlsStream {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<EpxTlsStream, JsError> {
        Err(jerr!("Use EpoxyClient.connect_tls() instead."))
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
    ) -> Result<EpxTlsStream, JsError> {
        let onerr = onerror.clone();
        let ret: Result<EpxTlsStream, JsError> = async move {
            let url = Uri::try_from(url).replace_err("Failed to parse URL")?;
            let url_host = url.host().replace_err("URL must have a host")?;
            let url_port = url.port().replace_err("URL must have a port")?.into();

            let io = tcp.get_tls_io(url_host, url_port).await?;
            let (rx, tx) = split(io);
            let mut rx = ReaderStream::new(rx);

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

            Ok(Self { tx, onerror, url: url.to_string() })
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
        let ret = self.tx.write_all(&payload.to_vec()).await;
        if let Err(ret) = ret {
            let _ = onerr.call1(&JsValue::null(), &jval!(format!("{}", ret)));
            Err(ret.into())
        } else {
            Ok(ret?)
        }
    }

    #[wasm_bindgen]
    pub async fn close(&mut self) -> Result<(), JsError> {
        self.tx.shutdown().await?;
        Ok(())
    }
}
