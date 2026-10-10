use std::{
	pin::Pin,
	sync::Arc,
	task::{ready, Context, Poll},
};

use futures::{channel::oneshot, FutureExt, Sink, SinkExt, Stream, StreamExt};

use crate::{
	mux::inner::{FlowControl, StreamInfo, WsEvent},
	packet::{ClosePacket, CloseReason, Packet},
	ws::{Payload, TransportWrite},
	LockedWebSocketWrite, WispError,
};

mod compat;
mod handles;
pub use compat::*;
pub use handles::*;

macro_rules! unlock_some {
	($unlock:expr, $x:expr) => {
		if let Err(err) = $x {
			$unlock.unlock();
			return Poll::Ready(Some(Err(err)));
		}
	};
}
macro_rules! unlock {
	($unlock:expr, $x:expr) => {
		if let Err(err) = $x {
			$unlock.unlock();
			return Poll::Ready(Err(err));
		}
	};
}

pub struct MuxStreamRead<W: TransportWrite> {
	inner: flume::r#async::RecvStream<'static, Payload>,
	write: LockedWebSocketWrite<W>,
	info: Arc<StreamInfo>,

	read_cnt: u32,
	chunk: Option<Payload>,
}

impl<W: TransportWrite> MuxStreamRead<W> {
	fn new(
		inner: flume::Receiver<Payload>,
		write: LockedWebSocketWrite<W>,
		info: Arc<StreamInfo>,
	) -> Self {
		Self {
			inner: inner.into_stream(),
			write,
			info,

			chunk: None,
			read_cnt: 0,
		}
	}

	pub fn get_stream_id(&self) -> u32 {
		self.info.id
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.inner.is_disconnected().then(|| self.info.get_reason())
	}

	pub fn into_async_read(self) -> MuxStreamAsyncRead<W> {
		MuxStreamAsyncRead::new(self)
	}
}

impl<W: TransportWrite> Stream for MuxStreamRead<W> {
	type Item = Result<Payload, WispError>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let was_reading = self.chunk.is_some();
		let chunk = if let Some(chunk) = self.chunk.take() {
			chunk
		} else {
			let Some(chunk) = ready!(self.inner.poll_next_unpin(cx)) else {
				return Poll::Ready(None);
			};
			chunk
		};

		macro_rules! ready {
			($x:expr) => {
				match $x {
					Poll::Ready(x) => x,
					Poll::Pending => {
						self.chunk = Some(chunk);
						return Poll::Pending;
					}
				}
			};
		}

		// a closed or dropped stream gets no buffer updates, but its buffered data is still read
		if self.info.flow_status == FlowControl::EnabledSendMessages && !self.inner.is_disconnected() {
			if !was_reading {
				self.read_cnt += 1;
			}

			if self.read_cnt > self.info.target_flow_control {
				ready!(self.write.poll_lock(cx));
				unlock_some!(self.write, ready!(self.write.get().poll_ready(cx)));
				let pkt =
					Packet::new_continue(self.info.id, self.info.flow_add(self.read_cnt)).encode();
				unlock_some!(self.write, self.write.get().start_send(pkt));
				self.write.unlock();

				self.read_cnt = 0;
			}
		}

		Poll::Ready(Some(Ok(chunk)))
	}
}

pub struct MuxStreamWrite<W: TransportWrite> {
	inner: flume::r#async::SendSink<'static, WsEvent<W>>,
	write: LockedWebSocketWrite<W>,
	info: Arc<StreamInfo>,

	chunk: Option<Payload>,

	oneshot: Option<oneshot::Receiver<Result<(), WispError>>>,
}

impl<W: TransportWrite> MuxStreamWrite<W> {
	fn new(
		inner: flume::Sender<WsEvent<W>>,
		write: LockedWebSocketWrite<W>,
		info: Arc<StreamInfo>,
	) -> Self {
		Self {
			inner: inner.into_sink(),
			write,
			info,

			chunk: None,

			oneshot: None,
		}
	}

	pub fn get_stream_id(&self) -> u32 {
		self.info.id
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.inner.is_disconnected().then(|| self.info.get_reason())
	}

	pub fn get_close_handle(&self) -> MuxStreamCloser<W> {
		MuxStreamCloser {
			info: self.info.clone(),
			inner: self.inner.sender().clone(),
		}
	}

	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream<W> {
		MuxProtocolExtensionStream {
			info: self.info.clone(),
			tx: self.write.clone(),
			inner: self.inner.sender().clone(),
		}
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&self, reason: CloseReason) -> Result<(), WispError> {
		if self.inner.is_disconnected() {
			return Err(WispError::StreamAlreadyClosed);
		}

		let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
		let evt = WsEvent::Close(self.info.id, ClosePacket { reason }, tx);

		self.inner
			.sender()
			.send_async(evt)
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;

		Ok(())
	}

	pub fn into_async_write(self) -> MuxStreamAsyncWrite<W> {
		MuxStreamAsyncWrite::new(self)
	}

	fn maybe_write(&mut self) -> Result<(), WispError> {
		if let Some(chunk) = self.chunk.take() {
			let packet = Packet::new_data(self.info.id, chunk).encode();
			self.write.get().start_send(packet)?;

			if self.info.flow_status == FlowControl::EnabledTrackAmount {
				self.info.flow_dec();
			}
		}

		Ok(())
	}
}

impl<W: TransportWrite> Sink<Payload> for MuxStreamWrite<W> {
	type Error = WispError;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		if self.inner.is_disconnected() {
			return Poll::Ready(Err(WispError::StreamAlreadyClosed));
		}

		if self.info.flow_status == FlowControl::EnabledTrackAmount && self.info.flow_empty() {
			self.info.flow_register(cx);
			return Poll::Pending;
		}

		if self.chunk.is_some() {
			ready!(self.write.poll_lock(cx));
			unlock!(self.write, ready!(self.write.get().poll_ready(cx)));
			unlock!(self.write, self.maybe_write());
			self.write.unlock();
		}

		Poll::Ready(Ok(()))
	}

	fn start_send(mut self: Pin<&mut Self>, item: Payload) -> Result<(), Self::Error> {
		debug_assert!(self.chunk.is_none());
		self.chunk = Some(item);

		Ok(())
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		ready!(self.write.poll_lock(cx));

		if self.chunk.is_some() {
			unlock!(self.write, ready!(self.write.get().poll_ready(cx)));
			unlock!(self.write, self.maybe_write());
		}
		unlock!(self.write, ready!(self.write.get().poll_flush(cx)));

		self.write.unlock();
		Poll::Ready(Ok(()))
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		if let Some(oneshot) = &mut self.oneshot {
			let ret = ready!(oneshot.poll_unpin(cx));
			self.oneshot.take();
			Poll::Ready(ret.map_err(|_| WispError::MuxMessageFailedToSend)?)
		} else {
			ready!(self.as_mut().poll_flush(cx))?;

			ready!(self.inner.poll_ready_unpin(cx))
				.map_err(|_| WispError::MuxMessageFailedToSend)?;

			let (tx, rx) = oneshot::channel();
			self.oneshot = Some(rx);

			let pkt = WsEvent::Close(
				self.info.id,
				ClosePacket {
					reason: CloseReason::Unknown,
				},
				tx,
			);

			self.inner
				.start_send_unpin(pkt)
				.map_err(|_| WispError::MuxMessageFailedToSend)?;

			Poll::Pending
		}
	}
}

pub struct MuxStream<W: TransportWrite> {
	read: MuxStreamRead<W>,
	write: MuxStreamWrite<W>,
}

impl<W: TransportWrite> MuxStream<W> {
	pub(crate) fn new(
		rx: flume::Receiver<Payload>,
		tx: flume::Sender<WsEvent<W>>,
		ws: LockedWebSocketWrite<W>,
		info: Arc<StreamInfo>,
	) -> Self {
		Self {
			read: MuxStreamRead::new(rx, ws.clone(), info.clone()),
			write: MuxStreamWrite::new(tx, ws, info),
		}
	}

	pub fn get_stream_id(&self) -> u32 {
		self.read.get_stream_id()
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.read.get_close_reason()
	}

	pub fn get_close_handle(&self) -> MuxStreamCloser<W> {
		self.write.get_close_handle()
	}

	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream<W> {
		self.write.get_protocol_extension_stream()
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&self, reason: CloseReason) -> Result<(), WispError> {
		self.write.close(reason).await
	}

	pub fn into_async_rw(self) -> MuxStreamAsyncRW<W> {
		MuxStreamAsyncRW::new(self)
	}

	pub fn into_split(self) -> (MuxStreamRead<W>, MuxStreamWrite<W>) {
		(self.read, self.write)
	}
}

impl<W: TransportWrite> Stream for MuxStream<W> {
	type Item = <MuxStreamRead<W> as Stream>::Item;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.read.poll_next_unpin(cx)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		self.read.size_hint()
	}
}

impl<W: TransportWrite> Sink<Payload> for MuxStream<W> {
	type Error = <MuxStreamWrite<W> as Sink<Payload>>::Error;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.write.poll_ready_unpin(cx)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Payload) -> Result<(), Self::Error> {
		self.write.start_send_unpin(item)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.write.poll_flush_unpin(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.write.poll_close_unpin(cx)
	}
}
