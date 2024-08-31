use std::{
	collections::HashMap,
	sync::{
		atomic::{AtomicBool, AtomicU32, Ordering},
		Arc,
	},
};

use crate::{
	extensions::AnyProtocolExtension,
	ws::{Frame, LockedWebSocketWrite, OpCode, Payload, WebSocketRead},
	AtomicCloseReason, ClosePacket, CloseReason, ConnectPacket, MuxStream, Packet, PacketType,
	Role, StreamType, WispError,
};
use bytes::{Bytes, BytesMut};
use event_listener::Event;
use flume as mpsc;
use futures::{channel::oneshot, FutureExt};

pub(crate) enum WsEvent {
	Close(Packet<'static>, oneshot::Sender<Result<(), WispError>>),
	CreateStream(
		StreamType,
		String,
		u16,
		oneshot::Sender<Result<MuxStream, WispError>>,
	),
	WispMessage(Frame<'static>, Option<Frame<'static>>),
	EndFut(Option<CloseReason>),
}

struct MuxMapValue {
	stream: mpsc::Sender<Bytes>,
	stream_type: StreamType,

	flow_control: Arc<AtomicU32>,
	flow_control_event: Arc<Event>,

	is_closed: Arc<AtomicBool>,
	close_reason: Arc<AtomicCloseReason>,
	is_closed_event: Arc<Event>,
}

pub struct MuxInner<R: WebSocketRead + Send> {
	rx: R,
	tx: LockedWebSocketWrite,
	extensions: Vec<AnyProtocolExtension>,
	role: Role,

	fut_rx: mpsc::Receiver<WsEvent>,
	fut_tx: mpsc::Sender<WsEvent>,
	fut_exited: Arc<AtomicBool>,

	stream_map: HashMap<u32, MuxMapValue>,

	buffer_size: u32,
	target_buffer_size: u32,

	server_tx: mpsc::Sender<(ConnectPacket, MuxStream)>,
}

impl<R: WebSocketRead + Send> MuxInner<R> {
	pub fn new_server(
		rx: R,
		tx: LockedWebSocketWrite,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> (
		Self,
		Arc<AtomicBool>,
		mpsc::Sender<WsEvent>,
		mpsc::Receiver<(ConnectPacket, MuxStream)>,
	) {
		let (fut_tx, fut_rx) = mpsc::bounded::<WsEvent>(256);
		let (server_tx, server_rx) = mpsc::unbounded::<(ConnectPacket, MuxStream)>();
		let ret_fut_tx = fut_tx.clone();
		let fut_exited = Arc::new(AtomicBool::new(false));

		(
			Self {
				rx,
				tx,

				fut_rx,
				fut_tx,
				fut_exited: fut_exited.clone(),

				extensions,
				buffer_size,
				target_buffer_size: ((buffer_size as u64 * 90) / 100) as u32,

				role: Role::Server,

				stream_map: HashMap::new(),

				server_tx,
			},
			fut_exited,
			ret_fut_tx,
			server_rx,
		)
	}

	pub fn new_client(
		rx: R,
		tx: LockedWebSocketWrite,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> (Self, Arc<AtomicBool>, mpsc::Sender<WsEvent>) {
		let (fut_tx, fut_rx) = mpsc::bounded::<WsEvent>(256);
		let (server_tx, _) = mpsc::unbounded::<(ConnectPacket, MuxStream)>();
		let ret_fut_tx = fut_tx.clone();
		let fut_exited = Arc::new(AtomicBool::new(false));

		(
			Self {
				rx,
				tx,

				fut_rx,
				fut_tx,
				fut_exited: fut_exited.clone(),

				extensions,
				buffer_size,
				target_buffer_size: 0,

				role: Role::Client,

				stream_map: HashMap::new(),

				server_tx,
			},
			fut_exited,
			ret_fut_tx,
		)
	}

	pub async fn into_future(mut self) -> Result<(), WispError> {
		let ret = self.stream_loop().await;

		self.fut_exited.store(true, Ordering::Release);

		for (_, stream) in self.stream_map.iter() {
			self.close_stream(stream, ClosePacket::new(CloseReason::Unknown));
		}
		self.stream_map.clear();

		let _ = self.tx.close().await;
		ret
	}

	async fn create_new_stream(
		&mut self,
		stream_id: u32,
		stream_type: StreamType,
	) -> Result<(MuxMapValue, MuxStream), WispError> {
		let (ch_tx, ch_rx) = mpsc::bounded(self.buffer_size as usize);

		let flow_control_event: Arc<Event> = Event::new().into();
		let flow_control: Arc<AtomicU32> = AtomicU32::new(self.buffer_size).into();

		let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();
		let close_reason: Arc<AtomicCloseReason> =
			AtomicCloseReason::new(CloseReason::Unknown).into();
		let is_closed_event: Arc<Event> = Event::new().into();

		Ok((
			MuxMapValue {
				stream: ch_tx,
				stream_type,

				flow_control: flow_control.clone(),
				flow_control_event: flow_control_event.clone(),

				is_closed: is_closed.clone(),
				close_reason: close_reason.clone(),
				is_closed_event: is_closed_event.clone(),
			},
			MuxStream::new(
				stream_id,
				self.role,
				stream_type,
				ch_rx,
				self.fut_tx.clone(),
				self.tx.clone(),
				is_closed,
				is_closed_event,
				close_reason,
				flow_control,
				flow_control_event,
				self.target_buffer_size,
			),
		))
	}

	fn close_stream(&self, stream: &MuxMapValue, close_packet: ClosePacket) {
		stream
			.close_reason
			.store(close_packet.reason, Ordering::Release);
		stream.is_closed.store(true, Ordering::Release);
		stream.is_closed_event.notify(usize::MAX);
		stream.flow_control.store(u32::MAX, Ordering::Release);
		stream.flow_control_event.notify(usize::MAX);
	}

	async fn get_message(&mut self) -> Result<Option<WsEvent>, WispError> {
		futures::select! {
			x = self.fut_rx.recv_async().fuse() => Ok(x.ok()),
			x = self.rx.wisp_read_split(&self.tx).fuse() => {
				let (mut frame, optional_frame) = x?;
				if frame.opcode == OpCode::Close {
					return Ok(None);
				}

				if let Some(ref extra_frame) = optional_frame {
					if frame.payload[0] != PacketType::Data(Payload::Bytes(BytesMut::new())).as_u8() {
						let mut payload = BytesMut::from(frame.payload);
						payload.extend_from_slice(&extra_frame.payload);
						frame.payload = Payload::Bytes(payload);
					}
				}

				Ok(Some(WsEvent::WispMessage(frame, optional_frame)))
			}
		}
	}

	async fn stream_loop(&mut self) -> Result<(), WispError> {
		let mut next_free_stream_id: u32 = 1;
		while let Some(msg) = self.get_message().await? {
			match msg {
				WsEvent::CreateStream(stream_type, host, port, channel) => {
					let ret: Result<MuxStream, WispError> = async {
						let stream_id = next_free_stream_id;
						let next_stream_id = next_free_stream_id
							.checked_add(1)
							.ok_or(WispError::MaxStreamCountReached)?;

						let (map_value, stream) =
							self.create_new_stream(stream_id, stream_type).await?;

						self.tx
							.write_frame(
								Packet::new_connect(stream_id, stream_type, port, host).into(),
							)
							.await?;

						self.stream_map.insert(stream_id, map_value);

						next_free_stream_id = next_stream_id;

						Ok(stream)
					}
					.await;
					let _ = channel.send(ret);
				}
				WsEvent::Close(packet, channel) => {
					if let Some(stream) = self.stream_map.remove(&packet.stream_id) {
						if let PacketType::Close(close) = packet.packet_type {
							self.close_stream(&stream, close);
						}
						let _ = channel.send(self.tx.write_frame(packet.into()).await);
					} else {
						let _ = channel.send(Err(WispError::InvalidStreamId));
					}
				}
				WsEvent::EndFut(x) => {
					if let Some(reason) = x {
						let _ = self
							.tx
							.write_frame(Packet::new_close(0, reason).into())
							.await;
					}
					break;
				}
				WsEvent::WispMessage(frame, optional_frame) => {
					if let Some(packet) = Packet::maybe_handle_extension(
						frame,
						&mut self.extensions,
						&mut self.rx,
						&mut self.tx,
					)
					.await?
					{
						let should_break = match self.role {
							Role::Server => {
								self.server_handle_packet(packet, optional_frame).await?
							}
							Role::Client => {
								self.client_handle_packet(packet, optional_frame).await?
							}
						};
						if should_break {
							break;
						}
					}
				}
			}
		}

		Ok(())
	}

	fn handle_close_packet(
		&mut self,
		stream_id: u32,
		inner_packet: ClosePacket,
	) -> Result<bool, WispError> {
		if stream_id == 0 {
			return Ok(true);
		}

		if let Some(stream) = self.stream_map.remove(&stream_id) {
			self.close_stream(&stream, inner_packet);
		}

		Ok(false)
	}

	fn handle_data_packet(
		&mut self,
		stream_id: u32,
		optional_frame: Option<Frame<'static>>,
		data: Payload<'static>,
	) -> Result<bool, WispError> {
		let mut data = BytesMut::from(data);

		if let Some(stream) = self.stream_map.get(&stream_id) {
			if let Some(extra_frame) = optional_frame {
				if data.is_empty() {
					data = extra_frame.payload.into();
				} else {
					data.extend_from_slice(&extra_frame.payload);
				}
			}
			let _ = stream.stream.try_send(data.freeze());
			if self.role == Role::Server && stream.stream_type == StreamType::Tcp {
				stream.flow_control.store(
					stream
						.flow_control
						.load(Ordering::Acquire)
						.saturating_sub(1),
					Ordering::Release,
				);
			}
		}

		Ok(false)
	}

	async fn server_handle_packet(
		&mut self,
		packet: Packet<'static>,
		optional_frame: Option<Frame<'static>>,
	) -> Result<bool, WispError> {
		use PacketType::*;
		match packet.packet_type {
			Continue(_) | Info(_) => Err(WispError::InvalidPacketType),
			Data(data) => self.handle_data_packet(packet.stream_id, optional_frame, data),
			Close(inner_packet) => self.handle_close_packet(packet.stream_id, inner_packet),

			Connect(inner_packet) => {
				let (map_value, stream) = self
					.create_new_stream(packet.stream_id, inner_packet.stream_type)
					.await?;
				self.server_tx
					.send_async((inner_packet, stream))
					.await
					.map_err(|_| WispError::MuxMessageFailedToSend)?;
				self.stream_map.insert(packet.stream_id, map_value);
				Ok(false)
			}
		}
	}

	async fn client_handle_packet(
		&mut self,
		packet: Packet<'static>,
		optional_frame: Option<Frame<'static>>,
	) -> Result<bool, WispError> {
		use PacketType::*;
		match packet.packet_type {
			Connect(_) | Info(_) => Err(WispError::InvalidPacketType),
			Data(data) => self.handle_data_packet(packet.stream_id, optional_frame, data),
			Close(inner_packet) => self.handle_close_packet(packet.stream_id, inner_packet),

			Continue(inner_packet) => {
				if let Some(stream) = self.stream_map.get(&packet.stream_id) {
					if stream.stream_type == StreamType::Tcp {
						stream
							.flow_control
							.store(inner_packet.buffer_remaining, Ordering::Release);
						let _ = stream.flow_control_event.notify(u32::MAX);
					}
				}
				Ok(false)
			}
		}
	}
}
