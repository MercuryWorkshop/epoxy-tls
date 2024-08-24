//! Abstraction over WebSocket implementations.
//!
//! Use the [`fastwebsockets`] implementation of these traits as an example for implementing them
//! for other WebSocket implementations.
//!
//! [`fastwebsockets`]: https://github.com/MercuryWorkshop/epoxy-tls/blob/multiplexed/wisp/src/fastwebsockets.rs
use std::{ops::Deref, sync::Arc};

use crate::WispError;
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use futures::lock::Mutex;

/// Payload of the websocket frame.
#[derive(Debug)]
pub enum Payload<'a> {
	/// Borrowed payload. Currently used when writing data.
	Borrowed(&'a [u8]),
	/// BytesMut payload. Currently used when reading data.
	Bytes(BytesMut),
}

impl From<BytesMut> for Payload<'static> {
	fn from(value: BytesMut) -> Self {
		Self::Bytes(value)
	}
}

impl<'a> From<&'a [u8]> for Payload<'a> {
	fn from(value: &'a [u8]) -> Self {
		Self::Borrowed(value)
	}
}

impl Payload<'_> {
	/// Turn a Payload<'a> into a Payload<'static> by copying the data.
	pub fn into_owned(self) -> Self {
		match self {
			Self::Bytes(x) => Self::Bytes(x),
			Self::Borrowed(x) => Self::Bytes(BytesMut::from(x)),
		}
	}
}

impl From<Payload<'_>> for BytesMut {
	fn from(value: Payload<'_>) -> Self {
		match value {
			Payload::Bytes(x) => x,
			Payload::Borrowed(x) => x.into(),
		}
	}
}

impl Deref for Payload<'_> {
	type Target = [u8];
	fn deref(&self) -> &Self::Target {
		match self {
			Self::Bytes(x) => x.deref(),
			Self::Borrowed(x) => x,
		}
	}
}

impl Clone for Payload<'_> {
	fn clone(&self) -> Self {
		match self {
			Self::Bytes(x) => Self::Bytes(x.clone()),
			Self::Borrowed(x) => Self::Bytes(BytesMut::from(*x)),
		}
	}
}

impl Buf for Payload<'_> {
	fn remaining(&self) -> usize {
		match self {
			Self::Bytes(x) => x.remaining(),
			Self::Borrowed(x) => x.remaining(),
		}
	}

	fn chunk(&self) -> &[u8] {
		match self {
			Self::Bytes(x) => x.chunk(),
			Self::Borrowed(x) => x.chunk(),
		}
	}

	fn advance(&mut self, cnt: usize) {
		match self {
			Self::Bytes(x) => x.advance(cnt),
			Self::Borrowed(x) => x.advance(cnt),
		}
	}
}

/// Opcode of the WebSocket frame.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
	/// Text frame.
	Text,
	/// Binary frame.
	Binary,
	/// Close frame.
	Close,
	/// Ping frame.
	Ping,
	/// Pong frame.
	Pong,
}

/// WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
	/// Whether the frame is finished or not.
	pub finished: bool,
	/// Opcode of the WebSocket frame.
	pub opcode: OpCode,
	/// Payload of the WebSocket frame.
	pub payload: Payload<'a>,
}

impl<'a> Frame<'a> {
	/// Create a new text frame.
	pub fn text(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Text,
			payload,
		}
	}

	/// Create a new binary frame.
	pub fn binary(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Binary,
			payload,
		}
	}

	/// Create a new close frame.
	pub fn close(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Close,
			payload,
		}
	}
}

/// Generic WebSocket read trait.
#[async_trait]
pub trait WebSocketRead {
	/// Read a frame from the socket.
	async fn wisp_read_frame(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, WispError>;

	/// Read a split frame from the socket.
	async fn wisp_read_split(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<(Frame<'static>, Option<Frame<'static>>), WispError> {
		self.wisp_read_frame(tx).await.map(|x| (x, None))
	}
}

#[async_trait]
impl WebSocketRead for Box<dyn WebSocketRead + Send> {
	async fn wisp_read_frame(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, WispError> {
		self.as_mut().wisp_read_frame(tx).await
	}

	async fn wisp_read_split(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<(Frame<'static>, Option<Frame<'static>>), WispError> {
		self.as_mut().wisp_read_split(tx).await
	}
}

/// Generic WebSocket write trait.
#[async_trait]
pub trait WebSocketWrite {
	/// Write a frame to the socket.
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError>;

	/// Close the socket.
	async fn wisp_close(&mut self) -> Result<(), WispError>;

	/// Write a split frame to the socket.
	async fn wisp_write_split(
		&mut self,
		header: Frame<'_>,
		body: Frame<'_>,
	) -> Result<(), WispError> {
		let mut payload = BytesMut::from(header.payload);
		payload.extend_from_slice(&body.payload);
		self.wisp_write_frame(Frame::binary(Payload::Bytes(payload)))
			.await
	}
}

#[async_trait]
impl WebSocketWrite for Box<dyn WebSocketWrite + Send> {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		self.as_mut().wisp_write_frame(frame).await
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		self.as_mut().wisp_close().await
	}

	async fn wisp_write_split(
		&mut self,
		header: Frame<'_>,
		body: Frame<'_>,
	) -> Result<(), WispError> {
		self.as_mut().wisp_write_split(header, body).await
	}
}

/// Locked WebSocket.
#[derive(Clone)]
pub struct LockedWebSocketWrite(Arc<Mutex<Box<dyn WebSocketWrite + Send>>>);

impl LockedWebSocketWrite {
	/// Create a new locked websocket.
	pub fn new(ws: Box<dyn WebSocketWrite + Send>) -> Self {
		Self(Mutex::new(ws).into())
	}

	/// Write a frame to the websocket.
	pub async fn write_frame(&self, frame: Frame<'_>) -> Result<(), WispError> {
		self.0.lock().await.wisp_write_frame(frame).await
	}

	pub(crate) async fn write_split(
		&self,
		header: Frame<'_>,
		body: Frame<'_>,
	) -> Result<(), WispError> {
		self.0.lock().await.wisp_write_split(header, body).await
	}

	/// Close the websocket.
	pub async fn close(&self) -> Result<(), WispError> {
		self.0.lock().await.wisp_close().await
	}
}

pub(crate) struct AppendingWebSocketRead<R>(pub Option<Frame<'static>>, pub R)
where
	R: WebSocketRead + Send;

#[async_trait]
impl<R> WebSocketRead for AppendingWebSocketRead<R>
where
	R: WebSocketRead + Send,
{
	async fn wisp_read_frame(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, WispError> {
		if let Some(x) = self.0.take() {
			return Ok(x);
		}
		self.1.wisp_read_frame(tx).await
	}

	async fn wisp_read_split(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<(Frame<'static>, Option<Frame<'static>>), WispError> {
		if let Some(x) = self.0.take() {
			return Ok((x, None));
		}
		self.1.wisp_read_split(tx).await
	}
}
