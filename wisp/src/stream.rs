use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub enum WsEvent {
    Send(Bytes),
    Close(crate::ClosePacket),
}

pub enum MuxEvent {
    Close(u32, u8, oneshot::Sender<Result<(), crate::WispError>>),
}

pub struct MuxStreamRead {
    pub stream_id: u32,
    rx: mpsc::UnboundedReceiver<WsEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamRead {
    pub async fn read(&mut self) -> Option<WsEvent> {
        if self.is_closed.load(Ordering::Acquire) {
            return None;
        }
        match self.rx.next().await? {
            WsEvent::Send(bytes) => Some(WsEvent::Send(bytes)),
            WsEvent::Close(packet) => {
                self.is_closed.store(true, Ordering::Release);
                Some(WsEvent::Close(packet))
            }
        }
    }
}

pub struct MuxStreamWrite<W>
where
    W: crate::ws::WebSocketWrite,
{
    pub stream_id: u32,
    tx: crate::ws::LockedWebSocketWrite<W>,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
}

impl<W: crate::ws::WebSocketWrite> MuxStreamWrite<W> {
    pub async fn write(&mut self, data: Bytes) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        self.tx
            .write_frame(crate::Packet::new_data(self.stream_id, data).into())
            .await
    }

    pub fn get_close_handle(&self) -> MuxStreamCloser {
        MuxStreamCloser {
            stream_id: self.stream_id,
            close_channel: self.close_channel.clone(),
            is_closed: self.is_closed.clone(),
        }
    }

    pub async fn close(&mut self, reason: u8) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), crate::WispError>>();
        self.close_channel
            .unbounded_send(MuxEvent::Close(self.stream_id, reason, tx))
            .map_err(|x| crate::WispError::Other(Box::new(x)))?;
        rx.await
            .map_err(|x| crate::WispError::Other(Box::new(x)))??;

        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }
}

impl<W: crate::ws::WebSocketWrite> Drop for MuxStreamWrite<W> {
    fn drop(&mut self) {
        let (tx, _) = oneshot::channel::<Result<(), crate::WispError>>();
        let _ = self
            .close_channel
            .unbounded_send(MuxEvent::Close(self.stream_id, 0x01, tx));
    }
}

pub struct MuxStream<W>
where
    W: crate::ws::WebSocketWrite,
{
    pub stream_id: u32,
    rx: MuxStreamRead,
    tx: MuxStreamWrite<W>,
}

impl<W: crate::ws::WebSocketWrite> MuxStream<W> {
    pub(crate) fn new(
        stream_id: u32,
        rx: mpsc::UnboundedReceiver<WsEvent>,
        tx: crate::ws::LockedWebSocketWrite<W>,
        close_channel: mpsc::UnboundedSender<MuxEvent>,
        is_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            stream_id,
            rx: MuxStreamRead {
                stream_id,
                rx,
                is_closed: is_closed.clone(),
            },
            tx: MuxStreamWrite {
                stream_id,
                tx,
                close_channel,
                is_closed: is_closed.clone(),
            },
        }
    }

    pub async fn read(&mut self) -> Option<WsEvent> {
        self.rx.read().await
    }

    pub async fn write(&mut self, data: Bytes) -> Result<(), crate::WispError> {
        self.tx.write(data).await
    }

    pub fn get_close_handle(&self) -> MuxStreamCloser {
        self.tx.get_close_handle()
    }

    pub async fn close(&mut self, reason: u8) -> Result<(), crate::WispError> {
        self.tx.close(reason).await
    }

    pub fn into_split(self) -> (MuxStreamRead, MuxStreamWrite<W>) {
        (self.rx, self.tx)
    }
}

pub struct MuxStreamCloser {
    stream_id: u32,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamCloser {
    pub async fn close(&mut self, reason: u8) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), crate::WispError>>();
        self.close_channel
            .unbounded_send(MuxEvent::Close(self.stream_id, reason, tx))
            .map_err(|x| crate::WispError::Other(Box::new(x)))?;
        rx.await
            .map_err(|x| crate::WispError::Other(Box::new(x)))??;
        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }
}
