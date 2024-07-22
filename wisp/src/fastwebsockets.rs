use std::ops::Deref;

use async_trait::async_trait;
use bytes::BytesMut;
use fastwebsockets::{
	CloseCode, FragmentCollectorRead, Frame, OpCode, Payload, WebSocketError, WebSocketRead,
	WebSocketWrite,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ws::LockedWebSocketWrite, WispError};

fn match_payload(payload: Payload<'_>) -> crate::ws::Payload<'_> {
	match payload {
		Payload::Bytes(x) => crate::ws::Payload::Bytes(x),
		Payload::Owned(x) => crate::ws::Payload::Bytes(BytesMut::from(x.deref())),
		Payload::BorrowedMut(x) => crate::ws::Payload::Borrowed(&*x),
		Payload::Borrowed(x) => crate::ws::Payload::Borrowed(x),
	}
}

fn match_payload_reverse(payload: crate::ws::Payload<'_>) -> Payload<'_> {
	match payload {
		crate::ws::Payload::Bytes(x) => Payload::Bytes(x),
		crate::ws::Payload::Borrowed(x) => Payload::Borrowed(x),
	}
}

fn payload_to_bytesmut(payload: Payload<'_>) -> BytesMut {
	match payload {
		Payload::Borrowed(borrowed) => BytesMut::from(borrowed),
		Payload::BorrowedMut(borrowed_mut) => BytesMut::from(&*borrowed_mut),
		Payload::Owned(owned) => BytesMut::from(owned.as_slice()),
		Payload::Bytes(b) => b,
	}
}

impl From<OpCode> for crate::ws::OpCode {
	fn from(opcode: OpCode) -> Self {
		use OpCode::*;
		match opcode {
			Continuation => {
				unreachable!("continuation should never be recieved when using a fragmentcollector")
			}
			Text => Self::Text,
			Binary => Self::Binary,
			Close => Self::Close,
			Ping => Self::Ping,
			Pong => Self::Pong,
		}
	}
}

impl<'a> From<Frame<'a>> for crate::ws::Frame<'a> {
	fn from(frame: Frame<'a>) -> Self {
		Self {
			finished: frame.fin,
			opcode: frame.opcode.into(),
			payload: match_payload(frame.payload),
		}
	}
}

impl<'a> From<crate::ws::Frame<'a>> for Frame<'a> {
	fn from(frame: crate::ws::Frame<'a>) -> Self {
		use crate::ws::OpCode::*;
		let payload = match_payload_reverse(frame.payload);
		match frame.opcode {
			Text => Self::text(payload),
			Binary => Self::binary(payload),
			Close => Self::close_raw(payload),
			Ping => Self::new(true, OpCode::Ping, None, payload),
			Pong => Self::pong(payload),
		}
	}
}

impl From<WebSocketError> for crate::WispError {
	fn from(err: WebSocketError) -> Self {
		if let WebSocketError::ConnectionClosed = err {
			Self::WsImplSocketClosed
		} else {
			Self::WsImplError(Box::new(err))
		}
	}
}

#[async_trait]
impl<S: AsyncRead + Unpin + Send> crate::ws::WebSocketRead for FragmentCollectorRead<S> {
	async fn wisp_read_frame(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<crate::ws::Frame<'static>, WispError> {
		Ok(self
			.read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
			.await?
			.into())
	}
}

#[async_trait]
impl<S: AsyncRead + Unpin + Send> crate::ws::WebSocketRead for WebSocketRead<S> {
	async fn wisp_read_frame(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<crate::ws::Frame<'static>, WispError> {
		let mut frame = self
			.read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
			.await?;

		if frame.opcode == OpCode::Continuation {
			return Err(WispError::WsImplError(Box::new(
				WebSocketError::InvalidContinuationFrame,
			)));
		}

		let mut buf = payload_to_bytesmut(frame.payload);
		let opcode = frame.opcode;

		while !frame.fin {
			frame = self
				.read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
				.await?;

			if frame.opcode != OpCode::Continuation {
				return Err(WispError::WsImplError(Box::new(
					WebSocketError::InvalidContinuationFrame,
				)));
			}

			buf.extend_from_slice(&frame.payload);
		}

		Ok(crate::ws::Frame {
			opcode: opcode.into(),
			payload: crate::ws::Payload::Bytes(buf),
			finished: frame.fin,
		})
	}

	async fn wisp_read_split(
		&mut self,
		tx: &LockedWebSocketWrite,
	) -> Result<(crate::ws::Frame<'static>, Option<crate::ws::Frame<'static>>), WispError> {
		let mut frame_cnt = 1;
		let mut frame = self
			.read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
			.await?;
		let mut extra_frame = None;

		if frame.opcode == OpCode::Continuation {
			return Err(WispError::WsImplError(Box::new(
				WebSocketError::InvalidContinuationFrame,
			)));
		}

		let mut buf = payload_to_bytesmut(frame.payload);
		let opcode = frame.opcode;

		while !frame.fin {
			frame = self
				.read_frame(&mut |frame| async { tx.write_frame(frame.into()).await })
				.await?;

			if frame.opcode != OpCode::Continuation {
				return Err(WispError::WsImplError(Box::new(
					WebSocketError::InvalidContinuationFrame,
				)));
			}
			if frame_cnt == 1 {
				let payload = payload_to_bytesmut(frame.payload);
				extra_frame = Some(crate::ws::Frame {
					opcode: opcode.into(),
					payload: crate::ws::Payload::Bytes(payload),
					finished: true,
				});
			} else if frame_cnt == 2 {
				let extra_payload = extra_frame.take().unwrap().payload;
				buf.extend_from_slice(&extra_payload);
				buf.extend_from_slice(&frame.payload);
			} else {
				buf.extend_from_slice(&frame.payload);
			}
			frame_cnt += 1;
		}

		Ok((
			crate::ws::Frame {
				opcode: opcode.into(),
				payload: crate::ws::Payload::Bytes(buf),
				finished: frame.fin,
			},
			extra_frame,
		))
	}
}

#[async_trait]
impl<S: AsyncWrite + Unpin + Send> crate::ws::WebSocketWrite for WebSocketWrite<S> {
	async fn wisp_write_frame(&mut self, frame: crate::ws::Frame<'_>) -> Result<(), WispError> {
		self.write_frame(frame.into()).await.map_err(|e| e.into())
	}

	async fn wisp_write_split(
		&mut self,
		header: crate::ws::Frame<'_>,
		body: crate::ws::Frame<'_>,
	) -> Result<(), WispError> {
		let mut header = Frame::from(header);
		header.fin = false;
		self.write_frame(header).await?;

		let mut body = Frame::from(body);
		body.opcode = OpCode::Continuation;
		self.write_frame(body).await?;

		Ok(())
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		self.write_frame(Frame::close(CloseCode::Normal.into(), b""))
			.await
			.map_err(|e| e.into())
	}
}
