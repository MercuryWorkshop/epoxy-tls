use fastwebsockets::{FragmentCollector, Frame, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::sync::Mutex;

type Ws = FragmentCollector<TokioIo<Upgraded>>;

pub struct LockedWebSocket(Arc<Mutex<Ws>>);

impl LockedWebSocket {
    pub fn new(ws: Ws) -> Self {
        Self(Arc::new(Mutex::new(ws)))
    }

    pub async fn read_frame(&self) -> Result<Frame, WebSocketError> {
        self.0.lock().await.read_frame().await
    }

    pub async fn write_frame(&self, frame: Frame<'_>) -> Result<(), WebSocketError> {
        self.0.lock().await.write_frame(frame).await
    }
}
