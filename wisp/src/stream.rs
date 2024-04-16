use crate::{sink_unfold, CloseReason, Packet, Role, StreamType, WispError};

pub use async_io_stream::IoStream;
use bytes::Bytes;
use event_listener::Event;
use flume as mpsc;
use futures::{
    channel::oneshot,
    select, stream,
    task::{Context, Poll},
    FutureExt, Sink, Stream,
};
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};

pub(crate) enum WsEvent {
    SendPacket(Packet, oneshot::Sender<Result<(), WispError>>),
    Close(Packet, oneshot::Sender<Result<(), WispError>>),
    CreateStream(
        StreamType,
        String,
        u16,
        oneshot::Sender<Result<MuxStream, WispError>>,
    ),
    EndFut(Option<CloseReason>),
}

/// Read side of a multiplexor stream.
pub struct MuxStreamRead {
    /// ID of the stream.
    pub stream_id: u32,
    /// Type of the stream.
    pub stream_type: StreamType,
    role: Role,
    tx: mpsc::Sender<WsEvent>,
    rx: mpsc::Receiver<Bytes>,
    is_closed: Arc<AtomicBool>,
    is_closed_event: Arc<Event>,
    flow_control: Arc<AtomicU32>,
    flow_control_read: AtomicU32,
    target_flow_control: u32,
}

impl MuxStreamRead {
    /// Read an event from the stream.
    pub async fn read(&mut self) -> Option<Bytes> {
        if self.is_closed.load(Ordering::Acquire) {
            return None;
        }
        let bytes = select! {
            x = self.rx.recv_async() => x.ok()?,
            _ = self.is_closed_event.listen().fuse() => return None
        };
        if self.role == Role::Server && self.stream_type == StreamType::Tcp {
            let val = self.flow_control_read.fetch_add(1, Ordering::AcqRel) + 1;
            if val > self.target_flow_control {
                let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
                self.tx
                    .send_async(WsEvent::SendPacket(
                        Packet::new_continue(
                            self.stream_id,
                            self.flow_control.fetch_add(val, Ordering::AcqRel) + val,
                        ),
                        tx,
                    ))
                    .await
                    .ok()?;
                rx.await.ok()?.ok()?;
                self.flow_control_read.store(0, Ordering::Release);
            }
        }
        Some(bytes)
    }

    pub(crate) fn into_stream(self) -> Pin<Box<dyn Stream<Item = Bytes> + Send>> {
        Box::pin(stream::unfold(self, |mut rx| async move {
            Some((rx.read().await?, rx))
        }))
    }
}

/// Write side of a multiplexor stream.
pub struct MuxStreamWrite {
    /// ID of the stream.
    pub stream_id: u32,
    /// Type of the stream.
    pub stream_type: StreamType,
    role: Role,
    tx: mpsc::Sender<WsEvent>,
    is_closed: Arc<AtomicBool>,
    continue_recieved: Arc<Event>,
    flow_control: Arc<AtomicU32>,
}

impl MuxStreamWrite {
    /// Write data to the stream.
    pub async fn write(&mut self, data: Bytes) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        if self.role == Role::Client
            && self.stream_type == StreamType::Tcp
            && self.flow_control.load(Ordering::Acquire) == 0
        {
            self.continue_recieved.listen().await;
        }
        let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
        self.tx
            .send_async(WsEvent::SendPacket(
                Packet::new_data(self.stream_id, data),
                tx,
            ))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)?;
        rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;
        if self.role == Role::Client && self.stream_type == StreamType::Tcp {
            self.flow_control.store(
                self.flow_control.load(Ordering::Acquire).saturating_sub(1),
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
            close_channel: self.tx.clone(),
            is_closed: self.is_closed.clone(),
        }
    }

    /// Close the stream. You will no longer be able to write or read after this has been called.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        self.is_closed.store(true, Ordering::Release);

        let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
        self.tx
            .send_async(WsEvent::Close(
                Packet::new_close(self.stream_id, reason),
                tx,
            ))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)?;
        rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;

        Ok(())
    }

    pub(crate) fn into_sink(self) -> Pin<Box<dyn Sink<Bytes, Error = WispError> + Send>> {
        let handle = self.get_close_handle();
        Box::pin(sink_unfold::unfold(
            self,
            |mut tx, data| async move {
                tx.write(data).await?;
                Ok(tx)
            },
            handle,
            move |mut handle| async {
                handle.close(CloseReason::Unknown).await?;
                Ok(handle)
            },
        ))
    }
}

impl Drop for MuxStreamWrite {
    fn drop(&mut self) {
        if !self.is_closed.load(Ordering::Acquire) {
            self.is_closed.store(true, Ordering::Release);
            let (tx, _) = oneshot::channel();
            let _ = self.tx.send(WsEvent::Close(
                Packet::new_close(self.stream_id, CloseReason::Unknown),
                tx,
            ));
        }
    }
}

/// Multiplexor stream.
pub struct MuxStream {
    /// ID of the stream.
    pub stream_id: u32,
    rx: MuxStreamRead,
    tx: MuxStreamWrite,
}

impl MuxStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: u32,
        role: Role,
        stream_type: StreamType,
        rx: mpsc::Receiver<Bytes>,
        tx: mpsc::Sender<WsEvent>,
        is_closed: Arc<AtomicBool>,
        is_closed_event: Arc<Event>,
        flow_control: Arc<AtomicU32>,
        continue_recieved: Arc<Event>,
        target_flow_control: u32,
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
                is_closed_event: is_closed_event.clone(),
                flow_control: flow_control.clone(),
                flow_control_read: AtomicU32::new(0),
                target_flow_control,
            },
            tx: MuxStreamWrite {
                stream_id,
                stream_type,
                role,
                tx,
                is_closed: is_closed.clone(),
                flow_control: flow_control.clone(),
                continue_recieved: continue_recieved.clone(),
            },
        }
    }

    /// Read an event from the stream.
    pub async fn read(&mut self) -> Option<Bytes> {
        self.rx.read().await
    }

    /// Write data to the stream.
    pub async fn write(&mut self, data: Bytes) -> Result<(), WispError> {
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
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
        self.tx.close(reason).await
    }

    /// Split the stream into read and write parts, consuming it.
    pub fn into_split(self) -> (MuxStreamRead, MuxStreamWrite) {
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
    close_channel: mpsc::Sender<WsEvent>,
    is_closed: Arc<AtomicBool>,
}

impl MuxStreamCloser {
    /// Close the stream. You will no longer be able to write or read after this has been called.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
        if self.is_closed.load(Ordering::Acquire) {
            return Err(WispError::StreamAlreadyClosed);
        }
        self.is_closed.store(true, Ordering::Release);

        let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
        self.close_channel
            .send_async(WsEvent::Close(
                Packet::new_close(self.stream_id, reason),
                tx,
            ))
            .await
            .map_err(|_| WispError::MuxMessageFailedToSend)?;
        rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;

        Ok(())
    }
}

pin_project! {
    /// Multiplexor stream that implements futures `Stream + Sink`.
    pub struct MuxStreamIo {
        #[pin]
        rx: Pin<Box<dyn Stream<Item = Bytes> + Send>>,
        #[pin]
        tx: Pin<Box<dyn Sink<Bytes, Error = WispError> + Send>>,
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
