use futures::{Future, task::{Poll, Context}};

impl<W: crate::ws::WebSocketWrite> tower::Service<hyper::Uri> for crate::ClientMux<W> {
    type Response = crate::tokioio::TokioIo<crate::MuxStream<W>>;
    type Error = crate::WispError;
    type Future = impl Future<Output = Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: hyper::Uri) -> Self::Future {

    }
}
