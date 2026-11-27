use std::{
	collections::VecDeque,
	future::poll_fn,
	sync::{
		Arc, Mutex,
		atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering},
	},
	task::{Context, Poll, Waker},
};

use futures::{SinkExt, StreamExt, channel::oneshot};
use rustc_hash::FxHashMap;

use crate::{
	WispError,
	extensions::AnyProtocolExtension,
	mux::stream_chan::{StreamChanEvent, StreamChanRecv},
	packet::{
		CloseReason, ConnectPacket, ContinuePacket, MaybeExtensionPacket, Packet, PacketType,
		StreamType,
	},
	stream::MuxStream,
	waiters::Waiter,
	ws::{Payload, TransportRead, TransportWrite},
};

pub(crate) enum WsEvent {
	CreateStream(ConnectPacket, oneshot::Sender<Result<MuxStream, WispError>>),
	Continue(u32, ContinuePacket),
	EndFut(Option<CloseReason>),
}

enum PumpPending {
	Connect(
		Payload,
		MuxStream,
		oneshot::Sender<Result<MuxStream, WispError>>,
	),
	Continue(Payload),
	EndFut(Payload),
}

enum FlushPending {
	Close(oneshot::Sender<Result<(), WispError>>),
}

enum PumpEvent {
	Extension(u8, u32, Payload),
	Ended,
}

pub(crate) type StreamMap = FxHashMap<u32, StreamMapValue>;

pub(crate) struct StreamMapValue {
	pub info: Arc<StreamInfo>,
	pub stream: flume::Sender<Payload>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum FlowControl {
	/// flow control completely disabled
	Disabled,
	/// flow control enabled
	/// - incoming: do not send buffer updates and no buffer
	/// - outgoing: track sent amount and wait
	EnabledTrackAmount,
	/// flow control enabled
	/// - incoming: send buffer updates and force buffer
	/// - outgoing: do not track sent amount and do not wait
	EnabledSendMessages,
}

const CLOSE_REASON_NOT_CLOSED: u16 = 0x100;
pub(crate) struct StreamInfo {
	pub id: u32,

	pub flow_status: FlowControl,
	pub target_flow_control: u32,
	flow_control: AtomicI64,
	close_reason: AtomicU16,
	flow_waker: Mutex<Waiter>,
}

impl StreamInfo {
	pub fn new(id: u32, flow_status: FlowControl, buffer_size: u32) -> Self {
		debug_assert_ne!(id, 0);

		// 90%
		#[expect(clippy::cast_possible_truncation)]
		let target = ((u64::from(buffer_size) * 90) / 100) as u32;

		Self {
			id,

			flow_status,
			target_flow_control: target,
			flow_control: AtomicI64::new(buffer_size.into()),
			flow_waker: Mutex::new(Waiter::Woken),
			close_reason: AtomicU16::new(CLOSE_REASON_NOT_CLOSED),
		}
	}

	pub fn flow_set(&self, amt: u32) {
		self.flow_control.store(amt.into(), Ordering::Relaxed);
	}
	pub fn flow_add(&self, amt: u32) -> i64 {
		self.flow_control.fetch_add(amt.into(), Ordering::Relaxed) + i64::from(amt)
	}
	pub fn flow_sub(&self, amt: u32) -> i64 {
		self.flow_control.fetch_sub(amt.into(), Ordering::Relaxed) - i64::from(amt)
	}
	pub fn flow_empty(&self) -> bool {
		self.flow_control.load(Ordering::Relaxed) <= 0
	}

	pub fn flow_register(&self, cx: &mut Context<'_>) {
		self.flow_waker
			.lock()
			.expect("flow_waker was poisoned")
			.register(cx);
	}
	pub fn flow_wake(&self) {
		let mut waiter = self.flow_waker.lock().expect("flow_waker was poisoned");
		if let Some(waker) = waiter.take() {
			drop(waiter);

			waker.wake();
		}
	}

	pub fn closed(&self) -> bool {
		self.close_reason.load(Ordering::Relaxed) != CLOSE_REASON_NOT_CLOSED
	}

	pub fn get_reason(&self) -> Option<CloseReason> {
		let reason = self.close_reason.load(Ordering::Relaxed);
		(reason != CLOSE_REASON_NOT_CLOSED).then(|| CloseReason::from(reason as u8))
	}
	pub fn set_reason(&self, reason: CloseReason) {
		self.close_reason
			.store(u16::from(u8::from(reason)), Ordering::Relaxed);
	}
}

pub(crate) trait MultiplexorActor: Send {
	fn handle_connect_packet(
		&mut self,
		stream: MuxStream,
		pkt: ConnectPacket,
	) -> Result<(), WispError>;

	fn handle_data_packet(
		&mut self,
		id: u32,
		pkt: Payload,
		streams: &mut StreamMap,
	) -> Result<(), WispError> {
		if let Some(stream) = streams.get(&id) {
			let _ = stream.stream.try_send(pkt);
		}
		Ok(())
	}

	fn handle_continue_packet(
		&mut self,
		id: u32,
		pkt: ContinuePacket,
		streams: &mut StreamMap,
	) -> Result<(), WispError>;

	fn get_flow_control(ty: StreamType, flow_stream_types: &[u8]) -> FlowControl;

	fn shutdown(&mut self) {}
}

pub(crate) struct MuxInner<R: TransportRead, W: TransportWrite, M: MultiplexorActor> {
	downgrade: Option<Packet<'static>>,

	rx: R,
	tx: W,
	tx_dirty: bool,
	tx_buf: VecDeque<PumpPending>,
	tx_flush: VecDeque<FlushPending>,

	stream_chan: StreamChanRecv,

	actor_rx: flume::r#async::RecvStream<'static, WsEvent>,
	actor_tx: flume::Sender<WsEvent>,
	closed: Arc<AtomicBool>,

	extensions: Vec<AnyProtocolExtension>,
	flow_stream_types: Box<[u8]>,

	mux: M,

	streams: StreamMap,
	current_id: u32,
	buffer_size: u32,
}

impl<R: TransportRead, W: TransportWrite, M: MultiplexorActor> Drop for MuxInner<R, W, M> {
	fn drop(&mut self) {
		self.shutdown();
	}
}

pub(crate) struct MuxInnerResult<R: TransportRead, W: TransportWrite, M: MultiplexorActor> {
	pub mux: MuxInner<R, W, M>,
	pub actor_tx: flume::Sender<WsEvent>,
	pub closed: Arc<AtomicBool>,
}

impl<R: TransportRead, W: TransportWrite, M: MultiplexorActor> MuxInner<R, W, M> {
	#[expect(clippy::new_ret_no_self)]
	pub fn new(
		rx: R,
		tx: W,
		mux: M,
		downgrade: Option<Packet<'static>>,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> MuxInnerResult<R, W, M> {
		let (actor_tx, actor_rx) = flume::unbounded();
		let closed = Arc::new(AtomicBool::new(false));

		let flow_extensions = extensions
			.iter()
			.flat_map(|x| x.get_congestion_stream_types())
			.copied()
			.chain(std::iter::once(StreamType::Tcp.into()))
			.collect();

		MuxInnerResult {
			actor_tx: actor_tx.clone(),
			closed: closed.clone(),
			mux: Self {
				downgrade,

				rx,
				tx,
				tx_dirty: false,
				tx_buf: VecDeque::new(),
				tx_flush: VecDeque::new(),

				stream_chan: StreamChanRecv::new(),

				actor_rx: actor_rx.into_stream(),
				actor_tx,
				closed,

				extensions,
				flow_stream_types: flow_extensions,

				mux,

				streams: StreamMap::default(),
				current_id: 0,
				buffer_size,
			},
		}
	}

	pub async fn into_future(mut self) -> Result<(), WispError> {
		let ret = self.pump().await;

		self.shutdown();

		let _ = self.tx.flush().await;
		let _ = self.tx.close().await;

		ret
	}

	/// Idempotent: runs at the end of `into_future` and again from `Drop`.
	fn shutdown(&mut self) {
		self.closed.store(true, Ordering::SeqCst);

		self.stream_chan.close();

		for stream in self.streams.drain() {
			Self::close_stream(stream.1, CloseReason::Unknown);
		}

		let mut cx = Context::from_waker(Waker::noop());
		while let Poll::Ready(Some(event)) = self.actor_rx.poll_next_unpin(&mut cx) {
			if let WsEvent::CreateStream(_, cb) = event {
				let _ = cb.send(Err(WispError::MuxTaskEnded));
			}
		}
		for pending in self.tx_buf.drain(..) {
			if let PumpPending::Connect(_, _, cb) = pending {
				let _ = cb.send(Err(WispError::MuxTaskEnded));
			}
		}
		for pending in self.tx_flush.drain(..) {
			match pending {
				FlushPending::Close(cb) => {
					let _ = cb.send(Err(WispError::MuxTaskEnded));
				}
			}
		}

		self.mux.shutdown();
	}

	async fn pump(&mut self) -> Result<(), WispError> {
		if let Some(packet) = self.downgrade.take()
			&& self.handle_packet(packet)?
		{
			return Ok(());
		}

		'outer: loop {
			match poll_fn(|cx| self.poll_pump(cx)).await? {
				PumpEvent::Extension(ty, stream_id, packet) => {
					for extension in &mut self.extensions {
						if extension.get_supported_packets().contains(&ty) {
							extension
								.handle_packet(ty, stream_id, packet, &mut self.rx, &mut self.tx)
								.await?;
							continue 'outer;
						}
					}
					return Err(WispError::InvalidPacketType(ty));
				}
				PumpEvent::Ended => {
					return Ok(());
				}
			}
		}
	}

	fn poll_pump(&mut self, cx: &mut Context<'_>) -> Poll<Result<PumpEvent, WispError>> {
		while let Poll::Ready(Some(e)) = self.actor_rx.poll_next_unpin(cx) {
			match e {
				WsEvent::CreateStream(connect, cb) => {
					let Some(stream_id) = self.current_id.checked_add(1) else {
						let _ = cb.send(Err(WispError::MaxStreamCountReached));
						continue;
					};
					self.current_id = stream_id;
					let stream = self.add_stream(stream_id, connect.stream_type);

					self.tx_buf.push_back(PumpPending::Connect(
						Packet {
							stream_id,
							packet_type: PacketType::Connect(connect),
						}
						.encode(),
						stream,
						cb,
					));
				}
				WsEvent::Continue(id, packet) => {
					if self.streams.contains_key(&id) {
						self.tx_buf.push_back(PumpPending::Continue(
							Packet {
								stream_id: id,
								packet_type: PacketType::Continue(packet),
							}
							.encode(),
						));
					}
				}
				WsEvent::EndFut(reason) => {
					if let Some(reason) = reason {
						self.tx_buf
							.push_back(PumpPending::EndFut(Packet::new_close(0, reason).encode()));
					} else {
						return Poll::Ready(Ok(PumpEvent::Ended));
					}
				}
			}
		}

		let mut budget_exhausted = true;
		for _ in 0..16 {
			match self.rx.poll_next_unpin(cx).map(|x| {
				x.map(|x| x.and_then(MaybeExtensionPacket::decode))
					.transpose()
			})? {
				Poll::Ready(Some(MaybeExtensionPacket::Packet(packet))) => {
					if self.handle_packet(packet)? {
						return Poll::Ready(Ok(PumpEvent::Ended));
					}
				}
				Poll::Ready(Some(MaybeExtensionPacket::Extension(ty, stream_id, packet))) => {
					return Poll::Ready(Ok(PumpEvent::Extension(ty, stream_id, packet)));
				}
				Poll::Ready(None) => {
					return Poll::Ready(Ok(PumpEvent::Ended));
				}
				Poll::Pending => {
					budget_exhausted = false;
					break;
				}
			}
		}
		if budget_exhausted {
			// reschedule since we may have more to read
			cx.waker().wake_by_ref();
		}

		while let Poll::Ready(()) = self.tx.poll_ready_unpin(cx)? {
			if let Some(control_message) = self.tx_buf.pop_front() {
				match control_message {
					PumpPending::Connect(msg, stream, cb) => {
						self.tx.start_send_unpin(msg)?;
						self.tx_dirty = true;
						let _ = cb.send(Ok(stream));
					}
					PumpPending::Continue(msg) => {
						self.tx.start_send_unpin(msg)?;
						self.tx_dirty = true;
					}
					PumpPending::EndFut(msg) => {
						self.tx.start_send_unpin(msg)?;
						self.tx_dirty = true;
						return Poll::Ready(Ok(PumpEvent::Ended));
					}
				}
			} else {
				match self.stream_chan.poll_next_unpin(cx) {
					Poll::Ready(Some(StreamChanEvent::Packet(id, _, packet))) => {
						if self.streams.contains_key(&id) {
							self.tx.start_send_unpin(packet)?;
							self.tx_dirty = true;
						}
					}
					Poll::Ready(Some(StreamChanEvent::Close(id, reason, cb))) => {
						if let Some(stream) = self.streams.remove(&id) {
							Self::close_stream(stream, reason);
							self.tx
								.start_send_unpin(Packet::new_close(id, reason).encode())?;
							self.tx_dirty = true;
							self.tx_flush.push_back(FlushPending::Close(cb));
						} else {
							let _ = cb.send(Ok(()));
						}
					}
					Poll::Ready(None) => return Poll::Ready(Ok(PumpEvent::Ended)),
					Poll::Pending => break,
				}
			}
			self.stream_chan.notify_sent();
		}

		if self.tx_dirty
			&& let Poll::Ready(()) = self.tx.poll_flush_unpin(cx)?
		{
			self.tx_dirty = false;
			for item in self.tx_flush.drain(..) {
				match item {
					FlushPending::Close(cb) => {
						let _ = cb.send(Ok(()));
					}
				}
			}
		}
		if !self.tx_dirty {
			self.stream_chan.notify_flushed();
		}

		Poll::Pending
	}

	fn add_stream(&mut self, id: u32, ty: StreamType) -> MuxStream {
		let flow = M::get_flow_control(ty, &self.flow_stream_types);
		// just drop packets if they go too fast to avoid us buffering
		let (data_tx, data_rx) = flume::bounded(self.buffer_size as usize);

		let info = Arc::new(StreamInfo::new(id, flow, self.buffer_size));
		let val = StreamMapValue {
			info: info.clone(),
			stream: data_tx,
		};
		self.streams.insert(id, val);

		MuxStream::new(
			data_rx,
			self.actor_tx.clone(),
			self.stream_chan.new_send(id),
			info,
		)
	}

	fn close_stream(stream: StreamMapValue, reason: CloseReason) {
		stream.info.set_reason(reason);
		stream.info.flow_wake();
		drop(stream.stream);
	}

	fn handle_packet(&mut self, packet: Packet<'static>) -> Result<bool, WispError> {
		use PacketType as P;
		match packet.packet_type {
			P::Connect(connect) => {
				let stream = self.add_stream(packet.stream_id, connect.stream_type);
				self.mux.handle_connect_packet(stream, connect)?;
				Ok(false)
			}

			P::Data(data) => {
				self.mux.handle_data_packet(
					packet.stream_id,
					data.into_owned(),
					&mut self.streams,
				)?;
				Ok(false)
			}

			P::Continue(cont) => {
				self.mux
					.handle_continue_packet(packet.stream_id, cont, &mut self.streams)?;
				Ok(false)
			}

			P::Close(close) => {
				if packet.stream_id == 0 {
					return Ok(true);
				}

				if let Some(stream) = self.streams.remove(&packet.stream_id) {
					Self::close_stream(stream, close.reason);
				}

				Ok(false)
			}
		}
	}
}
