use async_io_stream::IoStream;
use bytes::Bytes;
use event_listener::Event;
use futures::{
    channel::{mpsc, oneshot},
    sink, stream,
    task::{Context, Poll},
    Sink, Stream, StreamExt,
};
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};

pub enum WsEvent {
    Send(Bytes),
    Close(crate::ClosePacket),
}

pub enum MuxEvent {
    Close(u32, u8, oneshot::Sender<Result<(), crate::WispError>>),
}

pub struct MuxStreamRead<W>
where
    W: crate::ws::WebSocketWrite,
{
    pub stream_id: u32,
    role: crate::Role,
    tx: crate::ws::LockedWebSocketWrite<W>,
    rx: mpsc::UnboundedReceiver<WsEvent>,
    is_closed: Arc<AtomicBool>,
    flow_control: Arc<AtomicU32>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStreamRead<W> {
    pub async fn read(&mut self) -> Option<WsEvent> {
        if self.is_closed.load(Ordering::Acquire) {
            return None;
        }
        match self.rx.next().await? {
            WsEvent::Send(bytes) => {
                if self.role == crate::Role::Server {
                    let old_val = self.flow_control.fetch_add(1, Ordering::SeqCst);
                    self.tx
                        .write_frame(
                            crate::Packet::new_continue(self.stream_id, old_val + 1).into(),
                        )
                        .await
                        .ok()?;
                }
                Some(WsEvent::Send(bytes))
            }
            WsEvent::Close(packet) => {
                self.is_closed.store(true, Ordering::Release);
                Some(WsEvent::Close(packet))
            }
        }
    }

    pub(crate) fn into_stream(self) -> Pin<Box<dyn Stream<Item = Bytes> + Send>> {
        Box::pin(stream::unfold(self, |mut rx| async move {
            let evt = rx.read().await?;
            Some((
                match evt {
                    WsEvent::Send(bytes) => bytes,
                    WsEvent::Close(_) => return None,
                },
                rx,
            ))
        }))
    }
}

pub struct MuxStreamWrite<W>
where
    W: crate::ws::WebSocketWrite,
{
    pub stream_id: u32,
    role: crate::Role,
    tx: crate::ws::LockedWebSocketWrite<W>,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
    continue_recieved: Arc<Event>,
    flow_control: Arc<AtomicU32>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStreamWrite<W> {
    pub async fn write(&self, data: Bytes) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        if self.role == crate::Role::Client && self.flow_control.load(Ordering::Acquire) <= 0 {
            self.continue_recieved.listen().await;
        }
        self.tx
            .write_frame(crate::Packet::new_data(self.stream_id, data).into())
            .await?;
        if self.role == crate::Role::Client {
            self.flow_control.store(
                self.flow_control
                    .load(Ordering::Acquire)
                    .checked_add(1)
                    .unwrap_or(0),
                Ordering::Release,
            );
        }
        Ok(())
    }

    pub fn get_close_handle(&self) -> MuxStreamCloser {
        MuxStreamCloser {
            stream_id: self.stream_id,
            close_channel: self.close_channel.clone(),
            is_closed: self.is_closed.clone(),
        }
    }

    pub async fn close(&self, reason: u8) -> Result<(), crate::WispError> {
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

    pub(crate) fn into_sink(self) -> Pin<Box<dyn Sink<Bytes, Error = crate::WispError> + Send>> {
        Box::pin(sink::unfold(self, |tx, data| async move {
            tx.write(data).await?;
            Ok(tx)
        }))
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
    rx: MuxStreamRead<W>,
    tx: MuxStreamWrite<W>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStream<W> {
    pub(crate) fn new(
        stream_id: u32,
        role: crate::Role,
        rx: mpsc::UnboundedReceiver<WsEvent>,
        tx: crate::ws::LockedWebSocketWrite<W>,
        close_channel: mpsc::UnboundedSender<MuxEvent>,
        is_closed: Arc<AtomicBool>,
        flow_control: Arc<AtomicU32>,
        continue_recieved: Arc<Event>
    ) -> Self {
        Self {
            stream_id,
            rx: MuxStreamRead {
                stream_id,
                role,
                tx: tx.clone(),
                rx,
                is_closed: is_closed.clone(),
                flow_control: flow_control.clone(),
            },
            tx: MuxStreamWrite {
                stream_id,
                role,
                tx,
                close_channel,
                is_closed: is_closed.clone(),
                flow_control: flow_control.clone(),
                continue_recieved: continue_recieved.clone(),
            },
        }
    }

    pub async fn read(&mut self) -> Option<WsEvent> {
        self.rx.read().await
    }

    pub async fn write(&self, data: Bytes) -> Result<(), crate::WispError> {
        self.tx.write(data).await
    }

    pub fn get_close_handle(&self) -> MuxStreamCloser {
        self.tx.get_close_handle()
    }

    pub async fn close(&self, reason: u8) -> Result<(), crate::WispError> {
        self.tx.close(reason).await
    }

    pub fn into_split(self) -> (MuxStreamRead<W>, MuxStreamWrite<W>) {
        (self.rx, self.tx)
    }

    pub fn into_io(self) -> MuxStreamIo {
        MuxStreamIo {
            rx: self.rx.into_stream(),
            tx: self.tx.into_sink(),
        }
    }
}

pub struct MuxStreamCloser {
    stream_id: u32,
    close_channel: mpsc::UnboundedSender<MuxEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamCloser {
    pub async fn close(&self, reason: u8) -> Result<(), crate::WispError> {
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

pin_project! {
    pub struct MuxStreamIo {
        #[pin]
        rx: Pin<Box<dyn Stream<Item = Bytes> + Send>>,
        #[pin]
        tx: Pin<Box<dyn Sink<Bytes, Error = crate::WispError> + Send>>,
    }
}

impl MuxStreamIo {
    pub fn into_asyncrw(self) -> IoStream<MuxStreamIo, Vec<u8>> {
        IoStream::new(self)
    }
}

impl Stream for MuxStreamIo {
    type Item = Result<Vec<u8>, std::io::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project()
            .rx
            .poll_next(cx)
            .map(|x| x.map(|x| Ok(x.to_vec())))
    }
}

impl Sink<Vec<u8>> for MuxStreamIo {
    type Error = std::io::Error;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .tx
            .poll_ready(cx)
            .map_err(std::io::Error::other)
    }
    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.project()
            .tx
            .start_send(item.into())
            .map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .tx
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .tx
            .poll_close(cx)
            .map_err(std::io::Error::other)
    }
}
