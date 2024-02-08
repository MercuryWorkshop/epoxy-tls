use async_io_stream::IoStream;
use bytes::Bytes;
use event_listener::Event;
use futures::{
    channel::{mpsc, oneshot},
    stream,
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

/// Multiplexor event recieved from a Wisp stream.
pub enum MuxEvent {
    /// The other side has sent data.
    Send(Bytes),
    /// The other side has closed.
    Close(crate::ClosePacket),
}

pub(crate) enum WsEvent {
    Close(u32, crate::CloseReason, oneshot::Sender<Result<(), crate::WispError>>),
}

/// Read side of a multiplexor stream.
pub struct MuxStreamRead<W>
where
    W: crate::ws::WebSocketWrite,
{
    /// ID of the stream.
    pub stream_id: u32,
    /// Type of the stream.
    pub stream_type: crate::StreamType,
    role: crate::Role,
    tx: crate::ws::LockedWebSocketWrite<W>,
    rx: mpsc::UnboundedReceiver<MuxEvent>,
    is_closed: Arc<AtomicBool>,
    flow_control: Arc<AtomicU32>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStreamRead<W> {
    /// Read an event from the stream.
    pub async fn read(&mut self) -> Option<MuxEvent> {
        if self.is_closed.load(Ordering::Acquire) {
            return None;
        }
        match self.rx.next().await? {
            MuxEvent::Send(bytes) => {
                if self.role == crate::Role::Server && self.stream_type == crate::StreamType::Tcp {
                    let old_val = self.flow_control.fetch_add(1, Ordering::AcqRel);
                    self.tx
                        .write_frame(
                            crate::Packet::new_continue(self.stream_id, old_val + 1).into(),
                        )
                        .await
                        .ok()?;
                }
                Some(MuxEvent::Send(bytes))
            }
            MuxEvent::Close(packet) => {
                self.is_closed.store(true, Ordering::Release);
                Some(MuxEvent::Close(packet))
            }
        }
    }

    pub(crate) fn into_stream(self) -> Pin<Box<dyn Stream<Item = Bytes> + Send>> {
        Box::pin(stream::unfold(self, |mut rx| async move {
            let evt = rx.read().await?;
            Some((
                match evt {
                    MuxEvent::Send(bytes) => bytes,
                    MuxEvent::Close(_) => return None,
                },
                rx,
            ))
        }))
    }
}

/// Write side of a multiplexor stream.
pub struct MuxStreamWrite<W>
where
    W: crate::ws::WebSocketWrite,
{
    /// ID of the stream.
    pub stream_id: u32,
    role: crate::Role,
    tx: crate::ws::LockedWebSocketWrite<W>,
    close_channel: mpsc::UnboundedSender<WsEvent>,
    is_closed: Arc<AtomicBool>,
    continue_recieved: Arc<Event>,
    flow_control: Arc<AtomicU32>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStreamWrite<W> {
    /// Write data to the stream.
    pub async fn write(&self, data: Bytes) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        if self.role == crate::Role::Client && self.flow_control.load(Ordering::Acquire) == 0 {
            self.continue_recieved.listen().await;
        }
        self.tx
            .write_frame(crate::Packet::new_data(self.stream_id, data).into())
            .await?;
        if self.role == crate::Role::Client {
            self.flow_control.store(
                self.flow_control
                    .load(Ordering::Acquire)
                    .saturating_sub(1),
                Ordering::Release,
            );
        }
        Ok(())
    }

    /// Get a handle to close the connection.
    ///
    /// Useful to close the connection without having access to the stream.
    ///
    /// # Example
    /// ```
    /// let handle = stream.get_close_handle();
    /// if let Err(error) = handle_stream(stream) {
    ///     handle.close(0x01);
    /// }
    /// ```
    pub fn get_close_handle(&self) -> MuxStreamCloser {
        MuxStreamCloser {
            stream_id: self.stream_id,
            close_channel: self.close_channel.clone(),
            is_closed: self.is_closed.clone(),
        }
    }

    /// Close the stream. You will no longer be able to write or read after this has been called.
    pub async fn close(&self, reason: crate::CloseReason) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), crate::WispError>>();
        self.close_channel
            .unbounded_send(WsEvent::Close(self.stream_id, reason, tx))
            .map_err(|x| crate::WispError::Other(Box::new(x)))?;
        rx.await
            .map_err(|x| crate::WispError::Other(Box::new(x)))??;

        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn into_sink(self) -> Pin<Box<dyn Sink<Bytes, Error = crate::WispError> + Send>> {
        let handle = self.get_close_handle();
        Box::pin(crate::sink_unfold::unfold(self, |tx, data| async move {
            tx.write(data).await?;
            Ok(tx)
        }, move || {
            handle.close_sync(crate::CloseReason::Unknown)
        }))
    }
}

impl<W: crate::ws::WebSocketWrite> Drop for MuxStreamWrite<W> {
    fn drop(&mut self) {
        let (tx, _) = oneshot::channel::<Result<(), crate::WispError>>();
        let _ = self
            .close_channel
            .unbounded_send(WsEvent::Close(self.stream_id, crate::CloseReason::Unknown, tx));
    }
}

/// Multiplexor stream.
pub struct MuxStream<W>
where
    W: crate::ws::WebSocketWrite,
{
    /// ID of the stream.
    pub stream_id: u32,
    rx: MuxStreamRead<W>,
    tx: MuxStreamWrite<W>,
}

impl<W: crate::ws::WebSocketWrite + Send + 'static> MuxStream<W> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: u32,
        role: crate::Role,
        stream_type: crate::StreamType,
        rx: mpsc::UnboundedReceiver<MuxEvent>,
        tx: crate::ws::LockedWebSocketWrite<W>,
        close_channel: mpsc::UnboundedSender<WsEvent>,
        is_closed: Arc<AtomicBool>,
        flow_control: Arc<AtomicU32>,
        continue_recieved: Arc<Event>
    ) -> Self {
        Self {
            stream_id,
            rx: MuxStreamRead {
                stream_id,
                stream_type,
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

    /// Read an event from the stream.
    pub async fn read(&mut self) -> Option<MuxEvent> {
        self.rx.read().await
    }

    /// Write data to the stream.
    pub async fn write(&self, data: Bytes) -> Result<(), crate::WispError> {
        self.tx.write(data).await
    }

    /// Get a handle to close the connection.
    ///
    /// Useful to close the connection without having access to the stream.
    ///
    /// # Example
    /// ```
    /// let handle = stream.get_close_handle();
    /// if let Err(error) = handle_stream(stream) {
    ///     handle.close(0x01);
    /// }
    /// ```
    pub fn get_close_handle(&self) -> MuxStreamCloser {
        self.tx.get_close_handle()
    }

    /// Close the stream. You will no longer be able to write or read after this has been called.
    pub async fn close(&self, reason: crate::CloseReason) -> Result<(), crate::WispError> {
        self.tx.close(reason).await
    }

    /// Split the stream into read and write parts, consuming it.
    pub fn into_split(self) -> (MuxStreamRead<W>, MuxStreamWrite<W>) {
        (self.rx, self.tx)
    }

    /// Turn the stream into one that implements futures `Stream + Sink`, consuming it.
    pub fn into_io(self) -> MuxStreamIo {
        MuxStreamIo {
            rx: self.rx.into_stream(),
            tx: self.tx.into_sink(),
        }
    }
}

/// Close handle for a multiplexor stream.
#[derive(Clone)]
pub struct MuxStreamCloser {
    /// ID of the stream.
    pub stream_id: u32,
    close_channel: mpsc::UnboundedSender<WsEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamCloser {
    /// Close the stream. You will no longer be able to write or read after this has been called.
    pub async fn close(&self, reason: crate::CloseReason) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        let (tx, rx) = oneshot::channel::<Result<(), crate::WispError>>();
        self.close_channel
            .unbounded_send(WsEvent::Close(self.stream_id, reason, tx))
            .map_err(|x| crate::WispError::Other(Box::new(x)))?;
        rx.await
            .map_err(|x| crate::WispError::Other(Box::new(x)))??;
        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }

    /// Close the stream. This function does not check if it was actually closed.
    pub(crate) fn close_sync(&self, reason: crate::CloseReason) -> Result<(), crate::WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(crate::WispError::StreamAlreadyClosed);
        }
        let (tx, _) = oneshot::channel::<Result<(), crate::WispError>>();
        self.close_channel
            .unbounded_send(WsEvent::Close(self.stream_id, reason, tx))
            .map_err(|x| crate::WispError::Other(Box::new(x)))?;
        self.is_closed.store(true, Ordering::Release);
        Ok(())
    }
}

pin_project! {
    /// Multiplexor stream that implements futures `Stream + Sink`.
    pub struct MuxStreamIo {
        #[pin]
        rx: Pin<Box<dyn Stream<Item = Bytes> + Send>>,
        #[pin]
        tx: Pin<Box<dyn Sink<Bytes, Error = crate::WispError> + Send>>,
    }
}

impl MuxStreamIo {
    /// Turn the stream into one that implements futures `AsyncRead + AsyncWrite`.
    ///
    /// Enable the `tokio_io` feature to implement the tokio version of `AsyncRead` and
    /// `AsyncWrite`.
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
