use std::{pin::Pin, sync::Arc, task::Poll};

use futures_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector, TlsStream,
};
use futures_util::{future::Either, lock::Mutex, AsyncRead, AsyncWrite, Future};
use hyper_util_wasm::client::legacy::connect::{Connected, Connection};
use js_sys::{Array, Reflect, Uint8Array};
use pin_project_lite::pin_project;
use rustls_pki_types::{Der, TrustAnchor};
use tower_service::Service;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use wisp_mux::{
    extensions::{udp::UdpProtocolExtensionBuilder, ProtocolExtensionBuilder},
    ClientMux, IoStream, MuxStreamIo, StreamType, WispError,
};

use crate::{ws_wrapper::WebSocketWrapper, EpoxyClientOptions, EpoxyError};

fn object_to_trustanchor(obj: JsValue) -> Result<TrustAnchor<'static>, JsValue> {
    let subject: Uint8Array = Reflect::get(&obj, &"subject".into())?.dyn_into()?;
    let pub_key_info: Uint8Array =
        Reflect::get(&obj, &"subject_public_key_info".into())?.dyn_into()?;
    let name_constraints: Option<Uint8Array> = Reflect::get(&obj, &"name_constraints".into())
        .and_then(|x| x.dyn_into())
        .ok();
    Ok(TrustAnchor {
        subject: Der::from(subject.to_vec()),
        subject_public_key_info: Der::from(pub_key_info.to_vec()),
        name_constraints: name_constraints.map(|x| Der::from(x.to_vec())),
    })
}

pub struct StreamProvider {
    wisp_url: String,

    wisp_v2: bool,
    udp_extension: bool,
    websocket_protocols: Vec<String>,

    client_config: Arc<ClientConfig>,

    current_client: Arc<Mutex<Option<ClientMux>>>,
}

pub type ProviderUnencryptedStream = MuxStreamIo;
pub type ProviderUnencryptedAsyncRW = IoStream<ProviderUnencryptedStream, Vec<u8>>;
pub type ProviderTlsAsyncRW = TlsStream<ProviderUnencryptedAsyncRW>;
pub type ProviderAsyncRW = Either<ProviderTlsAsyncRW, ProviderUnencryptedAsyncRW>;

impl StreamProvider {
    pub fn new(
        wisp_url: String,
        certs: Array,
        options: &EpoxyClientOptions,
    ) -> Result<Self, EpoxyError> {
        let certs: Result<Vec<TrustAnchor>, JsValue> =
            certs.iter().map(object_to_trustanchor).collect();
        let certstore = RootCertStore::from_iter(certs.map_err(|_| EpoxyError::InvalidCertStore)?);
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(certstore)
                .with_no_client_auth(),
        );

        Ok(Self {
            wisp_url,
            current_client: Arc::new(Mutex::new(None)),
            wisp_v2: options.wisp_v2,
            udp_extension: options.udp_extension_required,
            websocket_protocols: options.websocket_protocols.clone(),
            client_config,
        })
    }

    async fn create_client(&self) -> Result<(), EpoxyError> {
        let extensions_vec: Vec<Box<dyn ProtocolExtensionBuilder + Send + Sync>> =
            vec![Box::new(UdpProtocolExtensionBuilder())];
        let extensions = if self.wisp_v2 {
            Some(extensions_vec.as_slice())
        } else {
            None
        };
        let (write, read) = WebSocketWrapper::connect(&self.wisp_url, &self.websocket_protocols)?;
        if !write.wait_for_open().await {
            return Err(EpoxyError::WebSocketConnectFailed);
        }
        let client = ClientMux::create(read, write, extensions).await?;
        let (mux, fut) = if self.udp_extension {
            client.with_udp_extension_required().await?
        } else {
            client.with_no_required_extensions()
        };
        self.current_client.lock().await.replace(mux);
        let current_client = self.current_client.clone();
        spawn_local(async move {
            fut.await;
            current_client.lock().await.take();
        });
        Ok(())
    }

    pub async fn get_stream(
        &self,
        stream_type: StreamType,
        host: String,
        port: u16,
    ) -> Result<ProviderUnencryptedStream, EpoxyError> {
        Box::pin(async {
            if let Some(mux) = self.current_client.lock().await.as_ref() {
                Ok(mux
                    .client_new_stream(stream_type, host, port)
                    .await?
                    .into_io())
            } else {
                self.create_client().await?;
                self.get_stream(stream_type, host, port).await
            }
        })
        .await
    }

    pub async fn get_asyncread(
        &self,
        stream_type: StreamType,
        host: String,
        port: u16,
    ) -> Result<ProviderUnencryptedAsyncRW, EpoxyError> {
        Ok(self
            .get_stream(stream_type, host, port)
            .await?
            .into_asyncrw())
    }

    pub async fn get_tls_stream(
        &self,
        host: String,
        port: u16,
    ) -> Result<ProviderTlsAsyncRW, EpoxyError> {
        let stream = self
            .get_asyncread(StreamType::Tcp, host.clone(), port)
            .await?;
        let connector = TlsConnector::from(self.client_config.clone());
        Ok(connector.connect(host.try_into()?, stream).await?.into())
    }
}

pin_project! {
    pub struct HyperIo {
        #[pin]
        inner: ProviderAsyncRW,
    }
}

impl hyper::rt::Read for HyperIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let buf_slice: &mut [u8] = unsafe { std::mem::transmute(buf.as_mut()) };
        match self.project().inner.poll_read(cx, buf_slice) {
            Poll::Ready(bytes_read) => {
                let bytes_read = bytes_read?;
                unsafe {
                    buf.advance(bytes_read);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for HyperIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_close(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

impl Connection for HyperIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[derive(Clone)]
pub struct StreamProviderService(pub Arc<StreamProvider>);

impl Service<hyper::Uri> for StreamProviderService {
    type Response = HyperIo;
    type Error = EpoxyError;
    type Future = Pin<Box<impl Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Uri) -> Self::Future {
        let provider = self.0.clone();
        Box::pin(async move {
            let scheme = req.scheme_str().ok_or(EpoxyError::InvalidUrlScheme)?;
            let host = req.host().ok_or(WispError::UriHasNoHost)?.to_string();
            let port = req.port_u16().ok_or(WispError::UriHasNoPort)?;
            Ok(HyperIo {
                inner: match scheme {
                    "https" => Either::Left(provider.get_tls_stream(host, port).await?),
                    "http" => {
                        Either::Right(provider.get_asyncread(StreamType::Tcp, host, port).await?)
                    }
                    _ => return Err(EpoxyError::InvalidUrlScheme),
                },
            })
        })
    }
}
