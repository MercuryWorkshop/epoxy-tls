use std::{
	io,
	pin::Pin,
	task::{Context, Poll, ready},
};

use futures::{
	AsyncBufRead, AsyncRead, AsyncWrite, SinkExt, Stream, StreamExt, TryStreamExt,
	stream::IntoAsyncRead,
};
use pin_project::pin_project;

use crate::{packet::CloseReason, ws::Payload};

use super::{MuxStream, MuxStreamRead, MuxStreamWrite};

struct MapToIo(MuxStreamRead);

impl Stream for MapToIo {
	type Item = Result<Payload, std::io::Error>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.0.poll_next_unpin(cx).map_err(std::io::Error::other)
	}
}

// TODO: don't use `futures` for this so get_close_reason etc can be implemented
#[pin_project]
pub struct MuxStreamAsyncRead {
	#[pin]
	inner: IntoAsyncRead<MapToIo>,
}

impl MuxStreamAsyncRead {
	pub(crate) fn new(inner: MuxStreamRead) -> Self {
		Self {
			inner: MapToIo(inner).into_async_read(),
		}
	}
}

impl AsyncRead for MuxStreamAsyncRead {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_read(cx, buf)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [io::IoSliceMut<'_>],
	) -> Poll<io::Result<usize>> {
		self.project().inner.poll_read_vectored(cx, bufs)
	}
}

impl AsyncBufRead for MuxStreamAsyncRead {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		self.project().inner.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().inner.consume(amt);
	}
}

pub struct MuxStreamAsyncWrite {
	inner: MuxStreamWrite,
}

impl MuxStreamAsyncWrite {
	pub(crate) fn new(inner: MuxStreamWrite) -> Self {
		Self { inner }
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.inner.get_close_reason()
	}
}

impl AsyncWrite for MuxStreamAsyncWrite {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		ready!(self.inner.poll_ready_unpin(cx)).map_err(io::Error::other)?;
		self.inner
			.start_send_ref(buf.into())
			.map_err(io::Error::other)?;
		Poll::Ready(Ok(buf.len()))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.inner.poll_flush_unpin(cx).map_err(io::Error::other)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.inner.poll_close_unpin(cx).map_err(io::Error::other)
	}
}

#[pin_project]
pub struct MuxStreamAsyncRW {
	#[pin]
	read: MuxStreamAsyncRead,
	#[pin]
	write: MuxStreamAsyncWrite,
}

impl MuxStreamAsyncRW {
	pub(crate) fn new(old: MuxStream) -> Self {
		Self {
			read: MuxStreamAsyncRead::new(old.read),
			write: MuxStreamAsyncWrite::new(old.write),
		}
	}

	pub fn into_split(self) -> (MuxStreamAsyncRead, MuxStreamAsyncWrite) {
		(self.read, self.write)
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.write.get_close_reason()
	}
}

impl AsyncRead for MuxStreamAsyncRW {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		self.project().read.poll_read(cx, buf)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [io::IoSliceMut<'_>],
	) -> Poll<io::Result<usize>> {
		self.project().read.poll_read_vectored(cx, bufs)
	}
}

impl AsyncBufRead for MuxStreamAsyncRW {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		self.project().read.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().read.consume(amt);
	}
}

impl AsyncWrite for MuxStreamAsyncRW {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		self.project().write.poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[io::IoSlice<'_>],
	) -> Poll<io::Result<usize>> {
		self.project().write.poll_write_vectored(cx, bufs)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().write.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.project().write.poll_close(cx)
	}
}
