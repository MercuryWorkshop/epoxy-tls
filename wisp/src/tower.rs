use crate::{tokioio::TokioIo, ws::WebSocketWrite, ClientMux, MuxStreamIo, StreamType, WispError};
use async_io_stream::IoStream;
use futures::{
    task::{Context, Poll},
    Future,
};
use std::sync::Arc;

pub struct ServiceWrapper<W: WebSocketWrite + Send + 'static>(pub Arc<ClientMux<W>>);

impl<W: WebSocketWrite + Send + 'static> tower_service::Service<hyper::Uri> for ServiceWrapper<W> {
    type Response = TokioIo<IoStream<MuxStreamIo, Vec<u8>>>;
    type Error = WispError;
    type Future = impl Future<Output = Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Uri) -> Self::Future {
        let mux = self.0.clone();
        async move {
            Ok(TokioIo::new(
                mux.client_new_stream(
                    StreamType::Tcp,
                    req.host().ok_or(WispError::UriHasNoHost)?.to_string(),
                    req.port().ok_or(WispError::UriHasNoPort)?.into(),
                )
                .await?
                .into_io()
                .into_asyncrw(),
            ))
        }
    }
}

impl<W: WebSocketWrite + Send + 'static> Clone for ServiceWrapper<W> { 
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
