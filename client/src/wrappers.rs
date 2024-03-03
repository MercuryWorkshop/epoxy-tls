use crate::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use event_listener::Event;
use futures_util::Stream;
use hyper::body::Body;
use js_sys::ArrayBuffer;
use pin_project_lite::pin_project;
use send_wrapper::SendWrapper;
use std::future::Future;
use tokio::sync::mpsc;
use web_sys::{BinaryType, MessageEvent, WebSocket};
use wisp_mux::{
    tokioio::TokioIo,
    tower::ServiceWrapper,
    ws::{Frame, LockedWebSocketWrite, WebSocketRead, WebSocketWrite},
    WispError,
};

pin_project! {
    pub struct IncomingBody {
        #[pin]
        incoming: hyper::body::Incoming,
    }
}

impl IncomingBody {
    pub fn new(incoming: hyper::body::Incoming) -> IncomingBody {
        IncomingBody { incoming }
    }
}

impl Stream for IncomingBody {
    type Item = std::io::Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let ret = this.incoming.poll_frame(cx);
        match ret {
            Poll::Ready(item) => Poll::<Option<Self::Item>>::Ready(match item {
                Some(frame) => frame
                    .map(|x| {
                        x.into_data()
                            .map_err(|_| std::io::Error::other("not data frame"))
                    })
                    .ok(),
                None => None,
            }),
            Poll::Pending => Poll::<Option<Self::Item>>::Pending,
        }
    }
}

pub struct TlsWispService<W>
where
    W: wisp_mux::ws::WebSocketWrite + Send + 'static,
{
    pub service: ServiceWrapper<W>,
    pub rustls_config: Arc<rustls::ClientConfig>,
}

impl<W: wisp_mux::ws::WebSocketWrite + Send + 'static> tower_service::Service<hyper::Uri>
    for TlsWispService<W>
{
    type Response = TokioIo<EpxIoStream>;
    type Error = WispError;
    type Future = Pin<Box<impl Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: http::Uri) -> Self::Future {
        let mut service = self.service.clone();
        let rustls_config = self.rustls_config.clone();
        Box::pin(async move {
            let uri_host = req
                .host()
                .ok_or(WispError::UriHasNoHost)?
                .to_string()
                .clone();
            let uri_parsed = Uri::builder()
                .authority(format!(
                    "{}:{}",
                    uri_host,
                    utils::get_url_port(&req).map_err(|_| WispError::UriHasNoPort)?
                ))
                .build()
                .map_err(|x| WispError::Other(Box::new(x)))?;
            let stream = service.call(uri_parsed).await?.into_inner();
            if utils::get_is_secure(&req).map_err(|_| WispError::InvalidUri)? {
                let connector = TlsConnector::from(rustls_config);
                Ok(TokioIo::new(Either::Left(
                    connector
                        .connect(
                            uri_host.try_into().map_err(|_| WispError::InvalidUri)?,
                            stream,
                        )
                        .await
                        .map_err(|x| WispError::Other(Box::new(x)))?,
                )))
            } else {
                Ok(TokioIo::new(Either::Right(stream)))
            }
        })
    }
}

impl<W: wisp_mux::ws::WebSocketWrite + Send + 'static> Clone for TlsWispService<W> {
    fn clone(&self) -> Self {
        Self {
            rustls_config: self.rustls_config.clone(),
            service: self.service.clone(),
        }
    }
}

#[derive(Debug)]
pub enum WebSocketError {
    Closed,
    Unknown,
    SendFailed,
}

impl std::fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use WebSocketError::*;
        match self {
            Closed => write!(f, "Websocket closed"),
            Unknown => write!(f, "Unknown error"),
            SendFailed => write!(f, "Send failed"),
        }
    }
}

impl std::error::Error for WebSocketError {}

impl From<WebSocketError> for WispError {
    fn from(err: WebSocketError) -> Self {
        Self::WsImplError(Box::new(err))
    }
}

pub enum WebSocketMessage {
    Close,
    Error,
    Message(Vec<u8>),
}

pub struct WebSocketWrapper {
    inner: SendWrapper<WebSocket>,

    // used to retain the closures
    #[allow(dead_code)]
    onopen: SendWrapper<Closure<dyn Fn()>>,
    #[allow(dead_code)]
    onclose: SendWrapper<Closure<dyn Fn()>>,
    #[allow(dead_code)]
    onerror: SendWrapper<Closure<dyn Fn()>>,
    #[allow(dead_code)]
    onmessage: SendWrapper<Closure<dyn Fn(MessageEvent)>>,
}

pub struct WebSocketReader {
    read_rx: mpsc::UnboundedReceiver<WebSocketMessage>,
}

impl WebSocketRead for WebSocketReader {
    async fn wisp_read_frame(
        &mut self,
        _: &LockedWebSocketWrite<impl WebSocketWrite>,
    ) -> Result<Frame, WispError> {
        use WebSocketMessage::*;
        match self
            .read_rx
            .recv()
            .await
            .ok_or(WispError::WsImplError(Box::new(WebSocketError::Closed)))?
        {
            Message(bin) => Ok(Frame::binary(bin.into())),
            Error => Err(WebSocketError::Unknown.into()),
            Close => Err(WebSocketError::Closed.into()),
        }
    }
}

impl WebSocketWrapper {
    pub async fn connect(
        url: String,
        protocols: Vec<String>,
    ) -> Result<(Self, WebSocketReader), JsValue> {
        let ws = if protocols.is_empty() {
            WebSocket::new(&url)
        } else {
            WebSocket::new_with_str_sequence(
                &url,
                &protocols
                    .iter()
                    .fold(Array::new(), |acc, x| {
                        acc.push(&jval!(x));
                        acc
                    })
                    .into(),
            )
        }
        .replace_err("Failed to make websocket")?;

        ws.set_binary_type(BinaryType::Arraybuffer);

        let (read_tx, read_rx) = mpsc::unbounded_channel();

        let open_event = Arc::new(Event::new());

        let open_event_tx = open_event.clone();
        let onopen = Closure::wrap(
            Box::new(move || while open_event_tx.notify(usize::MAX) == 0 {}) as Box<dyn Fn()>,
        );

        let onmessage_tx = read_tx.clone();
        let onmessage = Closure::wrap(Box::new(move |evt: MessageEvent| {
            if let Ok(arr) = evt.data().dyn_into::<ArrayBuffer>() {
                let _ =
                    onmessage_tx.send(WebSocketMessage::Message(Uint8Array::new(&arr).to_vec()));
            }
        }) as Box<dyn Fn(MessageEvent)>);

        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let onclose_tx = read_tx.clone();
        let onclose = Closure::wrap(Box::new(move || {
            let _ = onclose_tx.send(WebSocketMessage::Close);
        }) as Box<dyn Fn()>);

        let onerror_tx = read_tx.clone();
        let onerror = Closure::wrap(Box::new(move || {
            let _ = onerror_tx.send(WebSocketMessage::Error);
        }) as Box<dyn Fn()>);

        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        open_event.listen().await;

        Ok((
            Self {
                inner: SendWrapper::new(ws),
                onopen: SendWrapper::new(onopen),
                onclose: SendWrapper::new(onclose),
                onerror: SendWrapper::new(onerror),
                onmessage: SendWrapper::new(onmessage),
            },
            WebSocketReader { read_rx },
        ))
    }
}

impl WebSocketWrite for WebSocketWrapper {
    async fn wisp_write_frame(&mut self, frame: Frame) -> Result<(), WispError> {
        use wisp_mux::ws::OpCode::*;
        match frame.opcode {
            Binary => self
                .inner
                .send_with_u8_array(&frame.payload)
                .map_err(|_| WebSocketError::SendFailed.into()),
            Text => self
                .inner
                .send_with_u8_array(&frame.payload)
                .map_err(|_| WebSocketError::SendFailed.into()),
            Close => {
                let _ = self.inner.close();
                Ok(())
            }
            _ => Err(WispError::WsImplNotSupported),
        }
    }
}

impl Drop for WebSocketWrapper {
    fn drop(&mut self) {
        self.inner.set_onopen(None);
        self.inner.set_onclose(None);
        self.inner.set_onerror(None);
        self.inner.set_onmessage(None);
    }
}
