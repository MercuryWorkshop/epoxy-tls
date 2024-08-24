//! WebSocketRead + WebSocketWrite implementation for generic `Stream + Sink`s.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::error::Error;

use crate::{
	ws::{Frame, LockedWebSocketWrite, Payload, WebSocketRead, WebSocketWrite},
	WispError,
};

/// WebSocketRead implementation for generic `Stream`s.
pub struct GenericWebSocketRead<
	T: Stream<Item = Result<BytesMut, E>> + Send + Unpin,
	E: Error + Sync + Send + 'static,
>(T);

impl<T: Stream<Item = Result<BytesMut, E>> + Send + Unpin, E: Error + Sync + Send + 'static>
	GenericWebSocketRead<T, E>
{
	/// Create a new wrapper WebSocketRead implementation.
	pub fn new(stream: T) -> Self {
		Self(stream)
	}

	/// Get the inner Stream from the wrapper.
	pub fn into_inner(self) -> T {
		self.0
	}
}

#[async_trait]
impl<T: Stream<Item = Result<BytesMut, E>> + Send + Unpin, E: Error + Sync + Send + 'static>
	WebSocketRead for GenericWebSocketRead<T, E>
{
	async fn wisp_read_frame(
		&mut self,
		_tx: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, WispError> {
		match self.0.next().await {
			Some(data) => Ok(Frame::binary(Payload::Bytes(
				data.map_err(|x| WispError::WsImplError(Box::new(x)))?,
			))),
			None => Ok(Frame::close(Payload::Bytes(BytesMut::new()))),
		}
	}
}

/// WebSocketWrite implementation for generic `Sink`s.
pub struct GenericWebSocketWrite<
	T: Sink<Bytes, Error = E> + Send + Unpin,
	E: Error + Sync + Send + 'static,
>(T);

impl<T: Sink<Bytes, Error = E> + Send + Unpin, E: Error + Sync + Send + 'static>
	GenericWebSocketWrite<T, E>
{
	/// Create a new wrapper WebSocketWrite implementation.
	pub fn new(stream: T) -> Self {
		Self(stream)
	}

	/// Get the inner Sink from the wrapper.
	pub fn into_inner(self) -> T {
		self.0
	}
}

#[async_trait]
impl<T: Sink<Bytes, Error = E> + Send + Unpin, E: Error + Sync + Send + 'static> WebSocketWrite
	for GenericWebSocketWrite<T, E>
{
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		self.0
			.send(BytesMut::from(frame.payload).freeze())
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		self.0
			.close()
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))
	}
}
