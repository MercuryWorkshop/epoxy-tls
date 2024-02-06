use crate::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::Stream;
use hyper::body::Body;
use pin_project_lite::pin_project;
use std::future::Future;
use wisp_mux::{tokioio::TokioIo, tower::ServiceWrapper, WispError};

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
