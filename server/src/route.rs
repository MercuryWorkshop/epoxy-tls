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
use log::{debug, error};
use tokio::io::AsyncReadExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use wisp_mux::{
	generic::{GenericWebSocketRead, GenericWebSocketWrite},
	ws::{WebSocketRead, WebSocketWrite},
};

use crate::{
	config::SocketTransport,
	generate_stats,
	listener::{ServerStream, ServerStreamExt},
	stream::WebSocketStreamWrapper,
	CONFIG,
};

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
				debug!("sent server stats to http client");
				return Ok(Response::builder()
					.status(StatusCode::OK)
					.body(Body::new(x.into()))
					.unwrap());
			}
			Err(x) => {
				error!("failed to send stats to http client: {:?}", x);
				return Ok(Response::builder()
					.status(StatusCode::INTERNAL_SERVER_ERROR)
					.body(Body::new(x.to_string().into()))
					.unwrap());
			}
		}
	} else if !is_upgrade {
		debug!("sent non_ws_response to http client");
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
		debug!("sent non_ws_response to http client");
		return Ok(non_ws_resp());
	}

	Ok(resp)
}

pub async fn route(
	stream: ServerStream,
	callback: impl FnOnce(ServerRouteResult) + Clone + Send + 'static,
) -> anyhow::Result<()> {
	match CONFIG.server.transport {
		SocketTransport::WebSocket => {
			let stream = TokioIo::new(stream);

			let fut = Builder::new()
				.serve_connection(
					stream,
					service_fn(move |req| {
						let callback = callback.clone();

						ws_upgrade(req, |fut, wsproxy, udp, path| async move {
							let mut ws = fut.await.context("failed to await upgrade future")?;
							ws.set_max_message_size(CONFIG.server.max_message_size);
							ws.set_auto_pong(false);

							if wsproxy {
								let ws = WebSocketStreamWrapper(FragmentCollector::new(ws));
								(callback)(ServerRouteResult::WsProxy(ws, path, udp));
							} else {
								let (read, write) = ws.split(|x| {
									let parts =
										x.into_inner().downcast::<TokioIo<ServerStream>>().unwrap();
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

			let (read, write) = stream.split();
			let read = GenericWebSocketRead::new(FramedRead::new(read, codec.clone()));
			let write = GenericWebSocketWrite::new(FramedWrite::new(write, codec));

			(callback)(ServerRouteResult::Wisp((Box::new(read), Box::new(write))));
		}
	}
	Ok(())
}

pub type WispResult = (
	Box<dyn WebSocketRead + Send>,
	Box<dyn WebSocketWrite + Send>,
);

pub enum ServerRouteResult {
	Wisp(WispResult),
	WsProxy(WebSocketStreamWrapper, String, bool),
}
