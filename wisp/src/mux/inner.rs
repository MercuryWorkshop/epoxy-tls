use std::{
	pin::pin,
	sync::{
		atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
		Arc, Mutex,
	},
	task::Context,
};

use futures::{channel::oneshot, stream::unfold, SinkExt, StreamExt};
use rustc_hash::FxHashMap;

use crate::{
	extensions::AnyProtocolExtension,
	locked_sink::Waiter,
	packet::{
		ClosePacket, CloseReason, ConnectPacket, ContinuePacket, MaybeExtensionPacket, Packet,
		PacketType, StreamType,
	},
	stream::MuxStream,
	unfair_select::unfair_select,
	ws::{Payload, TransportRead, TransportWrite},
	LockedWebSocketWrite, WispError,
};

pub(crate) enum WsEvent<W: TransportWrite> {
	Close(u32, ClosePacket, oneshot::Sender<Result<(), WispError>>),
	CreateStream(
		ConnectPacket,
		oneshot::Sender<Result<MuxStream<W>, WispError>>,
	),
	WispMessage(Packet<'static>),
	EndFut(Option<CloseReason>),
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

pub(crate) struct StreamInfo {
	pub id: u32,

	pub flow_status: FlowControl,
	pub target_flow_control: u32,
	flow_control: AtomicU32,
	close_reason: AtomicU8,
	closed: AtomicBool,
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
			flow_control: AtomicU32::new(buffer_size),
			flow_waker: Mutex::new(Waiter::Woken),
			close_reason: AtomicU8::new(CloseReason::Unknown.into()),
			closed: AtomicBool::new(false),
		}
	}

	pub fn flow_set(&self, amt: u32) {
		self.flow_control.store(amt, Ordering::Relaxed);
	}
	pub fn flow_add(&self, amt: u32) -> u32 {
		let new = self
			.flow_control
			.load(Ordering::Relaxed)
			.saturating_add(amt);
		self.flow_control.store(new, Ordering::Relaxed);
		new
	}
	pub fn flow_sub(&self, amt: u32) -> u32 {
		let new = self
			.flow_control
			.load(Ordering::Relaxed)
			.saturating_sub(amt);
		self.flow_control.store(new, Ordering::Relaxed);
		new
	}
	pub fn flow_dec(&self) {
		self.flow_sub(1);
	}
	pub fn flow_empty(&self) -> bool {
		self.flow_control.load(Ordering::Relaxed) == 0
	}

	pub fn flow_register(&self, cx: &mut Context<'_>) {
		self.flow_waker
			.lock()
			.expect("flow_waker was poisoned")
			.register(cx);
	}
	pub fn flow_wake(&self) {
		let mut waiter = self.flow_waker.lock().expect("flow_waker was poisoned");
		if let Some(waker) = waiter.wake() {
			drop(waiter);

			waker.wake();
		}
	}

	pub fn get_reason(&self) -> CloseReason {
		self.close_reason.load(Ordering::Relaxed).into()
	}
	pub fn set_reason(&self, reason: CloseReason) {
		self.close_reason.store(reason.into(), Ordering::Relaxed);
	}
	pub fn set_closed_by_server(&self) {
		self.closed.store(true, Ordering::Release);
	}
	/// Only true after a server CLOSE, not when the connection drops
	pub fn is_closed(&self) -> bool {
		self.closed.load(Ordering::Acquire)
	}
}

pub(crate) trait MultiplexorActor<W: TransportWrite>: Send {
	fn handle_connect_packet(
		&mut self,
		stream: MuxStream<W>,
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
}

struct MuxStart<R: TransportRead, W: TransportWrite> {
	rx: R,
	downgrade: Option<Packet<'static>>,
	extensions: Vec<AnyProtocolExtension>,
	actor_rx: flume::Receiver<WsEvent<W>>,
}

pub(crate) struct MuxInner<R: TransportRead, W: TransportWrite, M: MultiplexorActor<W>> {
	start: Option<MuxStart<R, W>>,
	tx: LockedWebSocketWrite<W>,
	flow_stream_types: Box<[u8]>,

	mux: M,

	streams: StreamMap,
	current_id: u32,
	buffer_size: u32,

	actor_tx: flume::Sender<WsEvent<W>>,
}

pub(crate) struct MuxInnerResult<R: TransportRead, W: TransportWrite, M: MultiplexorActor<W>> {
	pub mux: MuxInner<R, W, M>,
	pub actor_tx: flume::Sender<WsEvent<W>>,
}

impl<R: TransportRead, W: TransportWrite, M: MultiplexorActor<W>> MuxInner<R, W, M> {
	#[expect(clippy::new_ret_no_self)]
	pub fn new(
		rx: R,
		tx: LockedWebSocketWrite<W>,
		mux: M,
		downgrade: Option<Packet<'static>>,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> MuxInnerResult<R, W, M> {
		let (actor_tx, actor_rx) = flume::unbounded();

		let flow_extensions = extensions
			.iter()
			.flat_map(|x| x.get_congestion_stream_types())
			.copied()
			.chain(std::iter::once(StreamType::Tcp.into()))
			.collect();

		MuxInnerResult {
			actor_tx: actor_tx.clone(),
			mux: Self {
				start: Some(MuxStart {
					rx,
					downgrade,
					extensions,
					actor_rx,
				}),
				tx,
				flow_stream_types: flow_extensions,

				mux,

				streams: StreamMap::default(),
				current_id: 0,
				buffer_size,

				actor_tx,
			},
		}
	}

	pub async fn into_future(mut self) -> Result<(), WispError> {
		let ret = self.entry().await;

		for stream in self.streams.drain() {
			Self::close_stream(
				stream.1,
				ClosePacket {
					reason: CloseReason::Unknown,
				},
			);
		}

		self.tx.lock().await;
		let _ = self.tx.get().close().await;
		self.tx.unlock();

		ret
	}

	async fn entry(&mut self) -> Result<(), WispError> {
		let MuxStart {
			rx,
			downgrade,
			extensions,
			actor_rx,
		} = self.start.take().ok_or(WispError::MuxTaskStarted)?;

		if let Some(packet) = downgrade {
			if self.handle_packet(packet)? {
				return Ok(());
			}
		}

		let read_stream = pin!(unfold(
			(rx, self.tx.clone(), extensions),
			|(mut rx, mut tx, mut extensions)| async {
				let ret: Result<Option<WsEvent<W>>, WispError> = async {
					if let Some(msg) = rx.next().await {
						match MaybeExtensionPacket::decode(msg?, &mut extensions, &mut rx, &mut tx)
							.await?
						{
							MaybeExtensionPacket::Packet(x) => Ok(Some(WsEvent::WispMessage(x))),
							MaybeExtensionPacket::ExtensionHandled => Ok(None),
						}
					} else {
						Ok(None)
					}
				}
				.await;
				ret.transpose().map(|x| (x, (rx, tx, extensions)))
			},
		));

		let mut stream = unfair_select(read_stream, actor_rx.into_stream().map(Ok));

		while let Some(msg) = stream.next().await {
			match msg? {
				WsEvent::CreateStream(connect, channel) => {
					let ret: Result<MuxStream<W>, WispError> = async {
						let (stream, stream_id) = self.create_stream(connect.stream_type)?;

						self.tx.lock().await;
						self.tx
							.get()
							.send(
								Packet {
									stream_id,
									packet_type: PacketType::Connect(connect),
								}
								.encode(),
							)
							.await?;
						self.tx.unlock();

						Ok(stream)
					}
					.await;
					let _ = channel.send(ret);
				}
				WsEvent::Close(id, close, channel) => {
					if let Some(stream) = self.streams.remove(&id) {
						Self::close_stream(stream, close);
						let pkt = Packet {
							stream_id: id,
							packet_type: PacketType::Close(close),
						}
						.encode();

						self.tx.lock().await;
						let ret = self.tx.get().send(pkt).await;
						self.tx.unlock();

						let _ = channel.send(ret);
					} else {
						let _ = channel.send(Err(WispError::InvalidStreamId(id)));
					}
				}
				WsEvent::EndFut(x) => {
					if let Some(reason) = x {
						self.tx.lock().await;
						let _ = self
							.tx
							.get()
							.send(Packet::new_close(0, reason).encode())
							.await;
						self.tx.unlock();
					}
					break;
				}
				WsEvent::WispMessage(packet) => {
					let should_break = self.handle_packet(packet)?;
					if should_break {
						break;
					}
				}
			}
		}

		Ok(())
	}

	fn create_stream(&mut self, ty: StreamType) -> Result<(MuxStream<W>, u32), WispError> {
		let id = self
			.current_id
			.checked_add(1)
			.ok_or(WispError::MaxStreamCountReached)?;
		self.current_id = id;
		Ok((self.add_stream(id, ty), id))
	}

	fn add_stream(&mut self, id: u32, ty: StreamType) -> MuxStream<W> {
		let flow = M::get_flow_control(ty, &self.flow_stream_types);
		let (data_tx, data_rx) = if flow == FlowControl::EnabledSendMessages {
			flume::bounded(self.buffer_size as usize)
		} else {
			flume::unbounded()
		};

		let info = Arc::new(StreamInfo::new(id, flow, self.buffer_size));
		let val = StreamMapValue {
			info: info.clone(),
			stream: data_tx,
		};
		self.streams.insert(id, val);

		MuxStream::new(data_rx, self.actor_tx.clone(), self.tx.clone(), info)
	}

	fn close_stream(stream: StreamMapValue, close: ClosePacket) {
		// Dropping the channel wakes the reader, so set the reason first
		stream.info.set_reason(close.reason);
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

			P::Close(close) => Ok(self.handle_close_packet(packet.stream_id, close)),
		}
	}

	fn handle_close_packet(&mut self, stream_id: u32, close: ClosePacket) -> bool {
		if stream_id == 0 {
			return true;
		}

		if let Some(stream) = self.streams.remove(&stream_id) {
			stream.info.set_closed_by_server();
			Self::close_stream(stream, close);
		}

		false
	}
}
