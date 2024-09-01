use anyhow::Context;
use tokio::{
	fs::{remove_file, try_exists},
	net::{tcp, unix, TcpListener, TcpStream, UnixListener, UnixStream},
};
use tokio_util::either::Either;
use uuid::Uuid;

use crate::{config::SocketType, CONFIG};

pub type ServerStream = Either<TcpStream, UnixStream>;
pub type ServerStreamRead = Either<tcp::OwnedReadHalf, unix::OwnedReadHalf>;
pub type ServerStreamWrite = Either<tcp::OwnedWriteHalf, unix::OwnedWriteHalf>;

pub trait ServerStreamExt {
	fn split(self) -> (ServerStreamRead, ServerStreamWrite);
}

impl ServerStreamExt for ServerStream {
	fn split(self) -> (ServerStreamRead, ServerStreamWrite) {
		match self {
			Self::Left(x) => {
				let (r, w) = x.into_split();
				(Either::Left(r), Either::Left(w))
			}
			Self::Right(x) => {
				let (r, w) = x.into_split();
				(Either::Right(r), Either::Right(w))
			}
		}
	}
}

pub enum ServerListener {
	Tcp(TcpListener),
	Unix(UnixListener),
}

impl ServerListener {
	pub async fn new() -> anyhow::Result<Self> {
		Ok(match CONFIG.server.socket {
			SocketType::Tcp => Self::Tcp(
				TcpListener::bind(&CONFIG.server.bind)
					.await
					.with_context(|| {
						format!("failed to bind to tcp address `{}`", CONFIG.server.bind)
					})?,
			),
			SocketType::Unix => {
				if try_exists(&CONFIG.server.bind).await? {
					remove_file(&CONFIG.server.bind).await?;
				}
				Self::Unix(UnixListener::bind(&CONFIG.server.bind).with_context(|| {
					format!("failed to bind to unix socket at `{}`", CONFIG.server.bind)
				})?)
			}
		})
	}

	pub async fn accept(&self) -> anyhow::Result<(ServerStream, String)> {
		match self {
			Self::Tcp(x) => {
				let (stream, addr) = x
					.accept()
					.await
					.context("failed to accept tcp connection")?;
				if CONFIG.server.tcp_nodelay {
					stream
						.set_nodelay(true)
						.context("failed to set tcp nodelay")?;
				}
				Ok((Either::Left(stream), addr.to_string()))
			}
			Self::Unix(x) => x
				.accept()
				.await
				.map(|(x, y)| {
					(
						Either::Right(x),
						y.as_pathname()
							.and_then(|x| x.to_str())
							.map(ToString::to_string)
							.unwrap_or_else(|| Uuid::new_v4().to_string() + "-unix_socket"),
					)
				})
				.context("failed to accept unix socket connection"),
		}
	}
}
