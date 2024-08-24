use std::{future::Future, io::Cursor};

use anyhow::Context;
use bytes::Bytes;
use fastwebsockets::{upgrade::UpgradeFut, FragmentCollector};
use http_body_util::Full;
use hyper::{
	body::Incoming, server::conn::http1::Builder, service::service_fn, Request, Response,
	StatusCode,
};
use hyper_util::rt::TokioIo;
use log::error;
use tokio::{
	fs::{remove_file, try_exists},
	io::AsyncReadExt,
	net::{tcp, unix, TcpListener, TcpStream, UnixListener, UnixStream},
};
use tokio_util::{
	codec::{FramedRead, FramedWrite, LengthDelimitedCodec},
	either::Either,
};
use uuid::Uuid;
use wisp_mux::{
	generic::{GenericWebSocketRead, GenericWebSocketWrite},
	ws::{WebSocketRead, WebSocketWrite},
};

use crate::{
	config::{SocketTransport, SocketType},
	generate_stats,
	stream::WebSocketStreamWrapper,
	CONFIG,
};

pub type ServerStream = Either<TcpStream, UnixStream>;
pub type ServerStreamRead = Either<tcp::OwnedReadHalf, unix::OwnedReadHalf>;
pub type ServerStreamWrite = Either<tcp::OwnedWriteHalf, unix::OwnedWriteHalf>;

type Body = Full<Bytes>;
fn non_ws_resp() -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.body(Body::new(CONFIG.server.non_ws_response.as_bytes().into()))
		.unwrap()
}

async fn ws_upgrade<T, R>(mut req: Request<Incoming>, callback: T) -> anyhow::Result<Response<Body>>
where
	T: FnOnce(UpgradeFut, bool, bool, String) -> R + Send + 'static,
	R: Future<Output = anyhow::Result<()>> + Send,
{
	let is_upgrade = fastwebsockets::upgrade::is_upgrade_request(&req);

	if !is_upgrade
		&& CONFIG.server.enable_stats_endpoint
		&& req.uri().path() == CONFIG.server.stats_endpoint
	{
		match generate_stats() {
			Ok(x) => {
				return Ok(Response::builder()
					.status(StatusCode::OK)
					.body(Body::new(x.into()))
					.unwrap())
			}
			Err(x) => {
				return Ok(Response::builder()
					.status(StatusCode::INTERNAL_SERVER_ERROR)
					.body(Body::new(x.to_string().into()))
					.unwrap())
			}
		}
	} else if !is_upgrade {
		return Ok(non_ws_resp());
	}

	let (resp, fut) = fastwebsockets::upgrade::upgrade(&mut req)?;
	// replace body of Empty<Bytes> with Full<Bytes>
	let resp = Response::from_parts(resp.into_parts().0, Body::new(Bytes::new()));

	if req
		.uri()
		.path()
		.starts_with(&(CONFIG.server.prefix.clone() + "/"))
	{
		tokio::spawn(async move {
			if let Err(err) = (callback)(fut, false, false, req.uri().path().to_string()).await {
				error!("error while serving client: {:?}", err);
			}
		});
	} else if CONFIG.wisp.allow_wsproxy {
		let udp = req.uri().query().unwrap_or_default() == "?udp";
		tokio::spawn(async move {
			if let Err(err) = (callback)(fut, false, udp, req.uri().path().to_string()).await {
				error!("error while serving client: {:?}", err);
			}
		});
	} else {
		return Ok(non_ws_resp());
	}

	Ok(resp)
}

pub trait ServerStreamExt {
	fn split(self) -> (ServerStreamRead, ServerStreamWrite);
	async fn route(
		self,
		callback: impl FnOnce(ServerRouteResult) + Clone + Send + 'static,
	) -> anyhow::Result<()>;
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

	async fn route(
		self,
		callback: impl FnOnce(ServerRouteResult) + Clone + Send + 'static,
	) -> anyhow::Result<()> {
		match CONFIG.server.transport {
			SocketTransport::WebSocket => {
				let stream = TokioIo::new(self);

				let fut = Builder::new()
					.serve_connection(
						stream,
						service_fn(move |req| {
							let callback = callback.clone();

							ws_upgrade(req, |fut, wsproxy, udp, path| async move {
								let mut ws = fut.await.context("failed to await upgrade future")?;
								ws.set_max_message_size(CONFIG.server.max_message_size);

								if wsproxy {
									let ws = WebSocketStreamWrapper(FragmentCollector::new(ws));
									(callback)(ServerRouteResult::WsProxy(ws, path, udp));
								} else {
									let (read, write) = ws.split(|x| {
										let parts = x
											.into_inner()
											.downcast::<TokioIo<ServerStream>>()
											.unwrap();
										let (r, w) = parts.io.into_inner().split();
										(Cursor::new(parts.read_buf).chain(r), w)
									});

									(callback)(ServerRouteResult::Wisp((
										Box::new(read),
										Box::new(write),
									)))
								}

								Ok(())
							})
						}),
					)
					.with_upgrades();

				if let Err(e) = fut.await {
					error!("error while serving client: {:?}", e);
				}
			}
			SocketTransport::LengthDelimitedLe => {
				let codec = LengthDelimitedCodec::builder()
					.little_endian()
					.max_frame_length(usize::MAX)
					.new_codec();

				let (read, write) = self.split();
				let read = GenericWebSocketRead::new(FramedRead::new(read, codec.clone()));
				let write = GenericWebSocketWrite::new(FramedWrite::new(write, codec));

				(callback)(ServerRouteResult::Wisp((Box::new(read), Box::new(write))));
			}
		}
		Ok(())
	}
}

pub type WispResult = (
	Box<dyn WebSocketRead + Send>,
	Box<dyn WebSocketWrite + Send>,
);

pub enum ServerRouteResult {
	Wisp(WispResult),
	WsProxy(WebSocketStreamWrapper, String, bool),
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
