use std::{
	pin::Pin,
	sync::Arc,
	task::{Context, Poll, ready},
};

use futures::{Sink, SinkExt, Stream, StreamExt, future::poll_fn};

use crate::{
	WispError,
	mux::inner::{FlowControl, StreamInfo, WsEvent},
	packet::{CloseReason, ContinuePacket},
	stream_chan::StreamChanSend,
	ws::{Payload, PayloadRef},
};

mod compat;
mod handles;
pub use compat::*;
pub use handles::*;

pub struct MuxStreamRead {
	actor_tx: flume::Sender<WsEvent>,
	inner: flume::r#async::RecvStream<'static, Payload>,
	info: Arc<StreamInfo>,
	read_cnt: u32,
}

impl MuxStreamRead {
	fn new(
		actor_tx: flume::Sender<WsEvent>,
		inner: flume::Receiver<Payload>,
		info: Arc<StreamInfo>,
	) -> Self {
		Self {
			actor_tx,
			inner: inner.into_stream(),
			info,
			read_cnt: 0,
		}
	}

	pub fn get_stream_id(&self) -> u32 {
		self.info.id
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.info.get_reason()
	}

	pub fn into_async_read(self) -> MuxStreamAsyncRead {
		MuxStreamAsyncRead::new(self)
	}
}

impl Stream for MuxStreamRead {
	type Item = Result<Payload, WispError>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let Some(chunk) = ready!(self.inner.poll_next_unpin(cx)) else {
			return Poll::Ready(None);
		};

		if self.info.flow_status == FlowControl::EnabledSendMessages {
			self.read_cnt += 1;

			if self.read_cnt > self.info.target_flow_control {
				let _ = self.actor_tx.send(WsEvent::Continue(
					self.info.id,
					ContinuePacket {
						buffer_remaining: self.info.flow_add(self.read_cnt),
					},
				));

				self.read_cnt = 0;
			}
		}

		Poll::Ready(Some(Ok(chunk)))
	}
}

pub struct MuxStreamWrite {
	chan: StreamChanSend,
	info: Arc<StreamInfo>,
}

impl MuxStreamWrite {
	fn new(chan: StreamChanSend, info: Arc<StreamInfo>) -> Self {
		Self { chan, info }
	}

	pub fn get_stream_id(&self) -> u32 {
		self.info.id
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.info.get_reason()
	}

	pub fn get_close_handle(&self) -> MuxStreamCloser {
		MuxStreamCloser {
			info: self.info.clone(),
			chan: self.chan.get_closer(),
		}
	}

	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream {
		MuxProtocolExtensionStream {
			info: self.info.clone(),
			chan: self.chan.clone(),
		}
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
		if self.info.closed() {
			return Err(WispError::StreamAlreadyClosed);
		}

		poll_fn(|cx| self.chan.poll_send_close(reason, cx)).await
	}

	pub fn into_async_write(self) -> MuxStreamAsyncWrite {
		MuxStreamAsyncWrite::new(self)
	}

	pub(crate) fn start_send_ref(&mut self, item: PayloadRef<'_>) -> Result<(), WispError> {
		if self.info.flow_status == FlowControl::EnabledTrackAmount {
			debug_assert!(!self.info.flow_empty());
			self.info.flow_dec();
		}
		self.chan.start_send_unpin(item.into())
	}
}

impl Sink<Payload> for MuxStreamWrite {
	type Error = WispError;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		if self.info.closed() {
			return Poll::Ready(Err(WispError::StreamAlreadyClosed));
		}

		if self.info.flow_status == FlowControl::EnabledTrackAmount && self.info.flow_empty() {
			self.info.flow_register(cx);
			if self.info.flow_empty() {
				return Poll::Pending;
			}
		}

		self.chan.poll_ready_unpin(cx)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Payload) -> Result<(), Self::Error> {
		self.start_send_ref(item.into())
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.chan.poll_flush_unpin(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.chan.poll_send_close(CloseReason::Unknown, cx)
	}
}

pub struct MuxStream {
	read: MuxStreamRead,
	write: MuxStreamWrite,
}

impl MuxStream {
	pub(crate) fn new(
		rx: flume::Receiver<Payload>,
		tx: flume::Sender<WsEvent>,
		chan: StreamChanSend,
		info: Arc<StreamInfo>,
	) -> Self {
		Self {
			read: MuxStreamRead::new(tx, rx, info.clone()),
			write: MuxStreamWrite::new(chan, info),
		}
	}

	pub fn get_stream_id(&self) -> u32 {
		self.read.get_stream_id()
	}

	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.read.get_close_reason()
	}

	pub fn get_close_handle(&self) -> MuxStreamCloser {
		self.write.get_close_handle()
	}

	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream {
		self.write.get_protocol_extension_stream()
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
		self.write.close(reason).await
	}

	pub fn into_async_rw(self) -> MuxStreamAsyncRW {
		MuxStreamAsyncRW::new(self)
	}

	pub fn into_split(self) -> (MuxStreamRead, MuxStreamWrite) {
		(self.read, self.write)
	}
}

impl Stream for MuxStream {
	type Item = <MuxStreamRead as Stream>::Item;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.read.poll_next_unpin(cx)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		self.read.size_hint()
	}
}

impl Sink<Payload> for MuxStream {
	type Error = <MuxStreamWrite as Sink<Payload>>::Error;

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
