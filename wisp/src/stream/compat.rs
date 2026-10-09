use std::{
	io,
	pin::Pin,
	sync::Arc,
	task::{ready, Context, Poll},
};

use futures::{
	channel::oneshot, stream::IntoAsyncRead, AsyncBufRead, AsyncRead, AsyncWrite, FutureExt,
	SinkExt, Stream, StreamExt, TryStreamExt,
};
use pin_project::pin_project;

use crate::{
	locked_sink::LockedWebSocketWrite,
	packet::{ClosePacket, CloseReason, Packet},
	ws::{Payload, TransportWrite},
	WispError,
};

use super::{MuxStream, MuxStreamRead, MuxStreamWrite, StreamInfo, WsEvent};

struct MapToIo<W: TransportWrite>(MuxStreamRead<W>);

impl<W: TransportWrite> Stream for MapToIo<W> {
	type Item = Result<Payload, std::io::Error>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.0.poll_next_unpin(cx).map_err(std::io::Error::other)
	}
}

// TODO: don't use `futures` for this so get_close_reason etc can be implemented
#[pin_project]
pub struct MuxStreamAsyncRead<W: TransportWrite> {
	#[pin]
	inner: IntoAsyncRead<MapToIo<W>>,
	info: Arc<StreamInfo>,
}

impl<W: TransportWrite> MuxStreamAsyncRead<W> {
	pub(crate) fn new(inner: MuxStreamRead<W>) -> Self {
		let info = inner.info.clone();
		Self {
			inner: MapToIo(inner).into_async_read(),
			info,
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.info.is_closed().then(|| self.info.get_reason())
	}
}

impl<W: TransportWrite> AsyncRead for MuxStreamAsyncRead<W> {
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

impl<W: TransportWrite> AsyncBufRead for MuxStreamAsyncRead<W> {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		self.project().inner.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().inner.consume(amt);
	}
}

#[cfg(feature = "embedded-io-async")]
const _: () = {
	use embedded_io_async::ErrorType;

	impl<W: TransportWrite> ErrorType for MuxStreamAsyncRead<W> {
		type Error = std::io::Error;
	}
	impl<W: TransportWrite> embedded_io_async::Read for MuxStreamAsyncRead<W> {
		async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
			use futures::AsyncReadExt;

			AsyncReadExt::read(self, buf).await
		}
	}
};

pub struct MuxStreamAsyncWrite<W: TransportWrite> {
	inner: flume::r#async::SendSink<'static, WsEvent<W>>,
	write: LockedWebSocketWrite<W>,
	info: Arc<StreamInfo>,

	oneshot: Option<oneshot::Receiver<Result<(), WispError>>>,
}

impl<W: TransportWrite> MuxStreamAsyncWrite<W> {
	pub(crate) fn new(inner: MuxStreamWrite<W>) -> Self {
		Self {
			inner: inner.inner,
			write: inner.write,
			info: inner.info,

			oneshot: None,
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.inner.is_disconnected().then(|| self.info.get_reason())
	}
}

impl<W: TransportWrite> AsyncWrite for MuxStreamAsyncWrite<W> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		ready!(self.write.poll_lock(cx));
		ready!(self.write.get().poll_ready(cx)).map_err(io::Error::other)?;

		let packet = Packet::new_data(self.info.id, buf);
		self.write
			.get()
			.start_send(packet.encode())
			.map_err(io::Error::other)?;

		self.write.unlock();
		Poll::Ready(Ok(buf.len()))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		ready!(self.write.poll_lock(cx));
		ready!(self.write.get().poll_flush(cx)).map_err(io::Error::other)?;
		self.write.unlock();
		Poll::Ready(Ok(()))
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		if let Some(oneshot) = &mut self.oneshot {
			let ret = ready!(oneshot.poll_unpin(cx));
			self.oneshot.take();
			Poll::Ready(
				ret.map_err(|_| io::Error::other(WispError::MuxMessageFailedToSend))?
					.map_err(io::Error::other),
			)
		} else {
			ready!(self.as_mut().poll_flush(cx))?;

			ready!(self.inner.poll_ready_unpin(cx))
				.map_err(|_| io::Error::other(WispError::MuxMessageFailedToSend))?;

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
				.map_err(|_| io::Error::other(WispError::MuxMessageFailedToSend))?;

			Poll::Pending
		}
	}
}

#[cfg(feature = "embedded-io-async")]
const _: () = {
	use embedded_io_async::ErrorType;

	impl<W: TransportWrite> ErrorType for MuxStreamAsyncWrite<W> {
		type Error = std::io::Error;
	}
	impl<W: TransportWrite> embedded_io_async::Write for MuxStreamAsyncWrite<W> {
		async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
			use futures::AsyncWriteExt;

			AsyncWriteExt::write(self, buf).await
		}
	}
};

#[pin_project]
pub struct MuxStreamAsyncRW<W: TransportWrite> {
	#[pin]
	read: MuxStreamAsyncRead<W>,
	#[pin]
	write: MuxStreamAsyncWrite<W>,
}

impl<W: TransportWrite> MuxStreamAsyncRW<W> {
	pub(crate) fn new(old: MuxStream<W>) -> Self {
		Self {
			read: MuxStreamAsyncRead::new(old.read),
			write: MuxStreamAsyncWrite::new(old.write),
		}
	}

	pub fn into_split(self) -> (MuxStreamAsyncRead<W>, MuxStreamAsyncWrite<W>) {
		(self.read, self.write)
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.read.get_close_reason()
	}
}

impl<W: TransportWrite> AsyncRead for MuxStreamAsyncRW<W> {
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

impl<W: TransportWrite> AsyncBufRead for MuxStreamAsyncRW<W> {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		self.project().read.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().read.consume(amt);
	}
}

impl<W: TransportWrite> AsyncWrite for MuxStreamAsyncRW<W> {
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
#[cfg(feature = "embedded-io-async")]
const _: () = {
	use embedded_io_async::ErrorType;

	impl<W: TransportWrite> ErrorType for MuxStreamAsyncRW<W> {
		type Error = std::io::Error;
	}
	impl<W: TransportWrite> embedded_io_async::Read for MuxStreamAsyncRW<W> {
		async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
			use futures::AsyncReadExt;

			AsyncReadExt::read(self, buf).await
		}
	}
	impl<W: TransportWrite> embedded_io_async::Write for MuxStreamAsyncRW<W> {
		async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
			use futures::AsyncWriteExt;

			AsyncWriteExt::write(self, buf).await
		}
	}
};

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use futures::{channel::mpsc, AsyncReadExt, SinkExt};
	use tokio::time::timeout;

	use crate::{
		packet::{CloseReason, Packet, StreamType},
		ws::Payload,
		ClientMux, WispError,
	};

	#[tokio::test]
	async fn close_reason_is_per_stream() {
		timeout(Duration::from_secs(5), async {
			let (to_client, from_server) = mpsc::unbounded::<Result<Payload, WispError>>();
			let (to_server, _server_rx) = mpsc::unbounded::<Payload>();
			let tx = to_server.sink_map_err(|_| WispError::WsImplSocketClosed);

			to_client
				.unbounded_send(Ok(Packet::new_continue(0, 128).encode()))
				.unwrap();
			let (mux, actor) = ClientMux::new(from_server, tx, None)
				.await
				.unwrap()
				.with_no_required_extensions();
			tokio::spawn(actor);

			let blocked = mux
				.new_stream(StreamType::Tcp, "blocked.test".into(), 443)
				.await
				.unwrap();
			let open = mux
				.new_stream(StreamType::Tcp, "open.test".into(), 443)
				.await
				.unwrap();
			let (blocked_id, open_id) = (blocked.get_stream_id(), open.get_stream_id());

			to_client
				.unbounded_send(Ok(Packet::new_close(
					blocked_id,
					CloseReason::ServerStreamBlockedAddress,
				)
				.encode()))
				.unwrap();
			let mut blocked = blocked.into_async_rw();
			let mut buf = [0; 8];
			assert_eq!(blocked.read(&mut buf).await.unwrap(), 0);
			assert_eq!(
				blocked.get_close_reason(),
				Some(CloseReason::ServerStreamBlockedAddress)
			);

			let mut open = open.into_async_rw();
			assert_eq!(open.get_close_reason(), None);
			to_client
				.unbounded_send(Ok(Packet::new_data(open_id, &b"hi"[..]).encode()))
				.unwrap();
			assert_eq!(open.read(&mut buf).await.unwrap(), 2);
			assert_eq!(&buf[..2], b"hi");
			assert_eq!(open.get_close_reason(), None);

			drop(to_client);
			let _ = open.read(&mut buf).await;
			assert_eq!(open.get_close_reason(), None);
		})
		.await
		.expect("close_reason_is_per_stream timed out");
	}
}
