use fastwebsockets::{WebSocketWrite, Frame, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::{io::WriteHalf, sync::Mutex};

type Ws = WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>;

#[derive(Clone)]
pub struct LockedWebSocketWrite(Arc<Mutex<Ws>>);

impl LockedWebSocketWrite {
    pub fn new(ws: Ws) -> Self {
        Self(Arc::new(Mutex::new(ws)))
    }

    pub async fn write_frame(&self, frame: Frame<'_>) -> Result<(), WebSocketError> {
        self.0.lock().await.write_frame(frame).await
    }
}
