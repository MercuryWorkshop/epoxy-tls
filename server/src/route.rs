use std::{fmt::Display, future::Future, io::Cursor};

use anyhow::Context;
use bytes::Bytes;
use fastwebsockets::{upgrade::UpgradeFut, FragmentCollector};
use http_body_util::Full;
use hyper::{
	body::Incoming, server::conn::http1::Builder, service::service_fn, HeaderMap, Request,
	Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, trace};
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
fn non_ws_resp() -> anyhow::Result<Response<Body>> {
	Ok(Response::builder()
		.status(StatusCode::OK)
		.body(Body::new(CONFIG.server.non_ws_response.as_bytes().into()))?)
}

fn send_stats() -> anyhow::Result<Response<Body>> {
	match generate_stats() {
		Ok(x) => {
			debug!("sent server stats to http client");
			Ok(Response::builder()
				.status(StatusCode::OK)
				.body(Body::new(x.into()))?)
		}
		Err(x) => {
			error!("failed to send stats to http client: {:?}", x);
			Ok(Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				.body(Body::new(x.to_string().into()))?)
		}
	}
}

fn get_header(headers: &HeaderMap, header: &str) -> Option<String> {
	headers
		.get(header)
		.and_then(|x| x.to_str().ok())
		.map(|x| x.to_string())
}

enum HttpUpgradeResult {
	Wisp,
	WsProxy(String, bool),
}

async fn ws_upgrade<F, R>(
	mut req: Request<Incoming>,
	stats_endpoint: Option<String>,
	callback: F,
) -> anyhow::Result<Response<Body>>
where
	F: FnOnce(UpgradeFut, HttpUpgradeResult, Option<String>) -> R + Send + 'static,
	R: Future<Output = anyhow::Result<()>> + Send,
{
	let is_upgrade = fastwebsockets::upgrade::is_upgrade_request(&req);

	if !is_upgrade {
		if let Some(stats_endpoint) = stats_endpoint {
			if req.uri().path() == stats_endpoint {
				return send_stats();
			} else {
				debug!("sent non_ws_response to http client");
				return non_ws_resp();
			}
		} else {
			debug!("sent non_ws_response to http client");
			return non_ws_resp();
		}
	}

	trace!("recieved request {:?}", req);

	let (resp, fut) = fastwebsockets::upgrade::upgrade(&mut req)?;
	// replace body of Empty<Bytes> with Full<Bytes>
	let resp = Response::from_parts(resp.into_parts().0, Body::new(Bytes::new()));

	let headers = req.headers();
	let ip_header = if CONFIG.server.use_real_ip_headers {
		get_header(headers, "x-real-ip").or_else(|| get_header(headers, "x-forwarded-for"))
	} else {
		None
	};

	if req
		.uri()
		.path()
		.starts_with(&(CONFIG.wisp.prefix.clone() + "/"))
	{
		tokio::spawn(async move {
			if let Err(err) = (callback)(fut, HttpUpgradeResult::Wisp, ip_header).await {
				error!("error while serving client: {:?}", err);
			}
		});
	} else if CONFIG.wisp.allow_wsproxy {
		let udp = req.uri().query().unwrap_or_default() == "?udp";
		tokio::spawn(async move {
			if let Err(err) = (callback)(
				fut,
				HttpUpgradeResult::WsProxy(req.uri().path().to_string(), udp),
				ip_header,
			)
			.await
			{
				error!("error while serving client: {:?}", err);
			}
		});
	} else {
		debug!("sent non_ws_response to http client");
		return non_ws_resp();
	}

	Ok(resp)
}

pub async fn route_stats(stream: ServerStream) -> anyhow::Result<()> {
	let stream = TokioIo::new(stream);
	Builder::new()
		.serve_connection(stream, service_fn(move |_| async { send_stats() }))
		.await?;
	Ok(())
}

pub async fn route(
	stream: ServerStream,
	stats_endpoint: Option<String>,
	callback: impl FnOnce(ServerRouteResult, Option<String>) + Clone + Send + 'static,
) -> anyhow::Result<()> {
	match CONFIG.server.transport {
		SocketTransport::WebSocket => {
			let stream = TokioIo::new(stream);

			Builder::new()
				.serve_connection(
					stream,
					service_fn(move |req| {
						let callback = callback.clone();

						ws_upgrade(
							req,
							stats_endpoint.clone(),
							|fut, res, maybe_ip| async move {
								let mut ws = fut.await.context("failed to await upgrade future")?;
								ws.set_max_message_size(CONFIG.server.max_message_size);
								ws.set_auto_pong(false);

								match res {
									HttpUpgradeResult::Wisp => {
										let (read, write) = ws.split(|x| {
											let parts = x
												.into_inner()
												.downcast::<TokioIo<ServerStream>>()
												.unwrap();
											let (r, w) = parts.io.into_inner().split();
											(Cursor::new(parts.read_buf).chain(r), w)
										});

										(callback)(
											ServerRouteResult::Wisp((
												Box::new(read),
												Box::new(write),
											)),
											maybe_ip,
										)
									}
									HttpUpgradeResult::WsProxy(path, udp) => {
										let ws = WebSocketStreamWrapper(FragmentCollector::new(ws));
										(callback)(
											ServerRouteResult::WsProxy(ws, path, udp),
											maybe_ip,
										);
									}
								}

								Ok(())
							},
						)
					}),
				)
				.with_upgrades()
				.await?;
		}
		SocketTransport::LengthDelimitedLe => {
			let codec = LengthDelimitedCodec::builder()
				.little_endian()
				.max_frame_length(usize::MAX)
				.new_codec();

			let (read, write) = stream.split();
			let read = GenericWebSocketRead::new(FramedRead::new(read, codec.clone()));
			let write = GenericWebSocketWrite::new(FramedWrite::new(write, codec));

			(callback)(
				ServerRouteResult::Wisp((Box::new(read), Box::new(write))),
				None,
			);
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

impl Display for ServerRouteResult {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
	    match self {
			Self::Wisp(_) => write!(f, "Wisp"),
			Self::WsProxy(_, path, udp) => write!(f, "WsProxy path {:?} udp {:?}", path, udp),
		}
	}
}
