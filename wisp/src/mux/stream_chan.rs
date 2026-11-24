use std::{
	pin::Pin,
	sync::{
		Arc, Mutex,
		atomic::{AtomicU64, AtomicUsize, Ordering},
	},
	task::{Context, Poll, ready},
};

use futures::{FutureExt, Sink, Stream, StreamExt, channel::oneshot};

use crate::{
	WispError,
	packet::{CloseReason, Packet},
	waiters::WaiterList,
	ws::{Payload, PayloadRef},
};

const HIGH_WATER_MARK: usize = 256 * 1024;
const LOW_WATER_MARK: usize = 64 * 1024;

pub enum StreamChanEvent {
	Packet(u32, usize, Payload),
	Close(u32, CloseReason, oneshot::Sender<Result<(), WispError>>),
}
impl StreamChanEvent {
	pub fn data_len(&self) -> Option<usize> {
		match self {
			Self::Packet(_, size, _) => Some(*size),
			Self::Close(_, _, _) => None,
		}
	}
}

struct StreamChan {
	send_waiters: Mutex<WaiterList>,
	to_send: AtomicUsize,

	flush_waiters: Mutex<WaiterList>,
	flush_queued: AtomicU64,
	flushed: AtomicU64,
}

pub struct StreamChanRecv {
	state: Arc<StreamChan>,
	chan: flume::r#async::RecvStream<'static, StreamChanEvent>,
	tx: flume::Sender<StreamChanEvent>,

	to_send: usize,
	to_flush: u64,
}
impl Drop for StreamChanRecv {
	fn drop(&mut self) {
		let mut locked = self
			.state
			.send_waiters
			.lock()
			.expect("send_waiters poisoned");
		let wakers = locked.take_all();
		drop(locked);
		for waker in wakers {
			waker.wake();
		}

		let mut locked = self
			.state
			.flush_waiters
			.lock()
			.expect("flush_waiters poisoned");
		let wakers = locked.take_all();
		drop(locked);
		for waker in wakers {
			waker.wake();
		}
	}
}
impl StreamChanRecv {
	pub fn new() -> Self {
		let (tx, rx) = flume::unbounded();
		Self {
			state: Arc::new(StreamChan {
				send_waiters: Mutex::new(WaiterList::new()),
				to_send: AtomicUsize::new(0),

				flush_waiters: Mutex::new(WaiterList::new()),
				flush_queued: AtomicU64::new(0),
				flushed: AtomicU64::new(0),
			}),
			chan: rx.into_stream(),
			tx,

			to_send: 0,
			to_flush: 0,
		}
	}

	pub fn notify_sent(&mut self) {
		if self.to_send == 0 {
			return;
		}

		let val = self
			.state
			.to_send
			.fetch_sub(self.to_send, Ordering::Relaxed)
			- self.to_send;

		self.to_flush += self.to_send as u64;
		self.to_send = 0;

		if val <= LOW_WATER_MARK {
			let mut locked = self
				.state
				.send_waiters
				.lock()
				.expect("send_waiters poisoned");
			let wakers = locked.take_all();
			drop(locked);
			for waker in wakers {
				waker.wake();
			}
		}
	}

	pub fn notify_flushed(&mut self) {
		if self.to_flush == 0 {
			return;
		}

		self.state
			.flushed
			.fetch_add(self.to_flush, Ordering::Relaxed);

		self.to_flush = 0;

		let mut locked = self
			.state
			.flush_waiters
			.lock()
			.expect("flush_waiters poisoned");
		let wakers = locked.take_all();
		drop(locked);
		for waker in wakers {
			waker.wake();
		}
	}

	pub fn new_send(&self, id: u32) -> StreamChanSend {
		StreamChanSend {
			stream_id: id,
			state: self.state.clone(),
			chan: self.tx.clone(),

			send_waker: None,

			flush_target: 0,
			flush_waker: None,

			close_slot: None,
		}
	}
}
impl Stream for StreamChanRecv {
	type Item = StreamChanEvent;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let Some(res) = ready!(self.chan.poll_next_unpin(cx)) else {
			return Poll::Ready(None);
		};

		if let Some(len) = res.data_len() {
			self.to_send += len;
		}

		Poll::Ready(Some(res))
	}
}

fn poll_close_impl(
	id: u32,
	chan: &mut flume::Sender<StreamChanEvent>,
	slot: &mut Option<oneshot::Receiver<Result<(), WispError>>>,
	reason: CloseReason,
	cx: &mut Context<'_>,
) -> Poll<Result<(), WispError>> {
	if let Some(recv) = slot {
		recv.poll_unpin(cx)
			.map_err(|_| WispError::MuxTaskEnded)
			.map(Result::flatten)
	} else {
		let (tx, rx) = oneshot::channel();
		chan.try_send(StreamChanEvent::Close(id, reason, tx))
			.map_err(|_| WispError::MuxTaskEnded)?;
		slot.replace(rx);
		poll_close_impl(id, chan, slot, reason, cx)
	}
}

pub struct StreamChanCloser {
	stream_id: u32,
	chan: flume::Sender<StreamChanEvent>,
	close_slot: Option<oneshot::Receiver<Result<(), WispError>>>,
}
impl StreamChanCloser {
	pub fn poll_send_close(
		&mut self,
		reason: CloseReason,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), WispError>> {
		poll_close_impl(
			self.stream_id,
			&mut self.chan,
			&mut self.close_slot,
			reason,
			cx,
		)
	}
}
impl Clone for StreamChanCloser {
	fn clone(&self) -> Self {
		Self {
			stream_id: self.stream_id,
			chan: self.chan.clone(),
			close_slot: None,
		}
	}
}

pub struct StreamChanSend {
	stream_id: u32,

	state: Arc<StreamChan>,
	chan: flume::Sender<StreamChanEvent>,

	send_waker: Option<usize>,

	flush_target: u64,
	flush_waker: Option<usize>,

	close_slot: Option<oneshot::Receiver<Result<(), WispError>>>,
}
impl StreamChanSend {
	pub fn get_closer(&self) -> StreamChanCloser {
		StreamChanCloser {
			stream_id: self.stream_id,
			chan: self.chan.clone(),
			close_slot: None,
		}
	}

	pub fn start_send_ext(&mut self, item: Payload) -> Result<(), WispError> {
		self.state.to_send.fetch_add(item.len(), Ordering::SeqCst);
		self.state
			.flush_queued
			.fetch_add(item.len() as u64, Ordering::SeqCst);

		self.chan
			.try_send(StreamChanEvent::Packet(self.stream_id, item.len(), item))
			.map_err(|_| WispError::MuxTaskEnded)?;

		self.flush_target = self.state.flush_queued.load(Ordering::SeqCst);
		Ok(())
	}

	pub fn poll_send_close(
		&mut self,
		reason: CloseReason,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), WispError>> {
		poll_close_impl(
			self.stream_id,
			&mut self.chan,
			&mut self.close_slot,
			reason,
			cx,
		)
	}
}
impl Clone for StreamChanSend {
	fn clone(&self) -> Self {
		Self {
			stream_id: self.stream_id,
			state: self.state.clone(),
			chan: self.chan.clone(),
			send_waker: None,
			flush_target: 0,
			flush_waker: None,
			close_slot: None,
		}
	}
}
impl Drop for StreamChanSend {
	fn drop(&mut self) {
		if let Some(waker) = self.send_waker.take() {
			self.state
				.send_waiters
				.lock()
				.expect("send_waiters was poisoned")
				.remove(waker);
		}

		if let Some(waker) = self.flush_waker.take() {
			self.state
				.flush_waiters
				.lock()
				.expect("flush_waiters was poisoned")
				.remove(waker);
		}
	}
}
impl Sink<PayloadRef<'_>> for StreamChanSend {
	type Error = WispError;

	fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		let this = self.get_mut();
		if this.send_waker.is_none()
			&& this.state.to_send.load(Ordering::Relaxed) <= HIGH_WATER_MARK
		{
			return Poll::Ready(Ok(()));
		}

		let mut locked = this
			.state
			.send_waiters
			.lock()
			.expect("send_waiters was poisoned");
		if this.state.to_send.load(Ordering::Relaxed) <= HIGH_WATER_MARK {
			locked.take_and_remove(&mut this.send_waker);
			return Poll::Ready(Ok(()));
		}

		if this.chan.is_disconnected() {
			locked.take_and_remove(&mut this.send_waker);
			return Poll::Ready(Err(WispError::MuxTaskEnded));
		}

		match this.send_waker {
			Some(key) => locked.update(key, cx),
			None => this.send_waker = Some(locked.add(cx)),
		}

		Poll::Pending
	}

	fn start_send(mut self: Pin<&mut Self>, item: PayloadRef<'_>) -> Result<(), Self::Error> {
		self.state.to_send.fetch_add(item.len(), Ordering::SeqCst);
		self.state
			.flush_queued
			.fetch_add(item.len() as u64, Ordering::SeqCst);

		self.chan
			.try_send(StreamChanEvent::Packet(
				self.stream_id,
				item.len(),
				Packet::new_data(self.stream_id, item).encode(),
			))
			.map_err(|_| WispError::MuxTaskEnded)?;

		self.flush_target = self.state.flush_queued.load(Ordering::SeqCst);
		Ok(())
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		let this = self.get_mut();
		if this.flush_waker.is_none()
			&& this.state.flushed.load(Ordering::Relaxed) >= this.flush_target
		{
			return Poll::Ready(Ok(()));
		}

		let mut locked = this
			.state
			.flush_waiters
			.lock()
			.expect("flush_waiters was poisoned");
		if this.state.flushed.load(Ordering::Relaxed) >= this.flush_target {
			locked.take_and_remove(&mut this.flush_waker);
			return Poll::Ready(Ok(()));
		}

		if this.chan.is_disconnected() {
			locked.take_and_remove(&mut this.flush_waker);
			return Poll::Ready(Err(WispError::MuxTaskEnded));
		}

		match this.flush_waker {
			Some(key) => locked.update(key, cx),
			None => this.flush_waker = Some(locked.add(cx)),
		}

		Poll::Pending
	}

	fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Poll::Ready(Ok(()))
	}
}
