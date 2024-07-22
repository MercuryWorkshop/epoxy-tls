#![feature(ip)]

use std::{env::args, fmt::Write, fs::read_to_string};

use bytes::Bytes;
use config::{validate_config_cache, Config};
use dashmap::DashMap;
use handle::{handle_wisp, handle_wsproxy};
use http_body_util::Full;
use hyper::{
	body::Incoming, server::conn::http1::Builder, service::service_fn, Request, Response,
	StatusCode,
};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use log::{error, info};
use stream::ServerListener;
use tokio::signal::unix::{signal, SignalKind};
use uuid::Uuid;
use wisp_mux::{ConnectPacket, StreamType};

mod config;
mod handle;
mod stream;

type Client = (DashMap<Uuid, (ConnectPacket, ConnectPacket)>, bool);

lazy_static! {
	pub static ref CONFIG: Config = {
		if let Some(path) = args().nth(1) {
			toml::from_str(&read_to_string(path).unwrap()).unwrap()
		} else {
			Config::default()
		}
	};
	pub static ref CLIENTS: DashMap<String, Client> = DashMap::new();
}

type Body = Full<Bytes>;
fn non_ws_resp() -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.body(Body::new(CONFIG.server.non_ws_response.as_bytes().into()))
		.unwrap()
}

async fn upgrade(mut req: Request<Incoming>, id: String) -> anyhow::Result<Response<Body>> {
	if CONFIG.server.enable_stats_endpoint && req.uri().path() == CONFIG.server.stats_endpoint {
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
	} else if !fastwebsockets::upgrade::is_upgrade_request(&req) {
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
			CLIENTS.insert(id.clone(), (DashMap::new(), false));
			if let Err(e) = handle_wisp(fut, id.clone()).await {
				error!("error while handling upgraded client: {:?}", e);
			};
			CLIENTS.remove(&id)
		});
	} else if CONFIG.wisp.allow_wsproxy {
		let udp = req.uri().query().unwrap_or_default() == "?udp";
		tokio::spawn(async move {
			CLIENTS.insert(id.clone(), (DashMap::new(), true));
			if let Err(e) = handle_wsproxy(fut, id.clone(), req.uri().path().to_string(), udp).await
			{
				error!("error while handling upgraded client: {:?}", e);
			};
			CLIENTS.remove(&id)
		});
	} else {
		return Ok(non_ws_resp());
	}

	Ok(resp)
}

fn format_stream_type(stream_type: StreamType) -> &'static str {
	match stream_type {
		StreamType::Tcp => "tcp",
		StreamType::Udp => "udp",
		StreamType::Unknown(_) => unreachable!(),
	}
}

fn generate_stats() -> Result<String, std::fmt::Error> {
	let mut out = String::new();
	let len = CLIENTS.len();
	writeln!(
		&mut out,
		"{} clients connected{}",
		len,
		if len != 0 { ":" } else { "" }
	)?;

	for client in CLIENTS.iter() {
		let len = client.value().0.len();

		writeln!(
			&mut out,
			"\tClient \"{}\"{}: {} streams connected{}",
			client.key(),
			if client.value().1 { " (wsproxy)" } else { "" },
			len,
			if len != 0 && CONFIG.server.verbose_stats {
				":"
			} else {
				""
			}
		)?;

		if CONFIG.server.verbose_stats {
			for stream in client.value().0.iter() {
				writeln!(
					&mut out,
					"\t\tStream \"{}\": {}",
					stream.key(),
					format_stream_type(stream.value().0.stream_type)
				)?;
				writeln!(
					&mut out,
					"\t\t\tRequested: {}:{}",
					stream.value().0.destination_hostname,
					stream.value().0.destination_port
				)?;
				writeln!(
					&mut out,
					"\t\t\tResolved: {}:{}",
					stream.value().1.destination_hostname,
					stream.value().1.destination_port
				)?;
			}
		}
	}
	Ok(out)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
	env_logger::builder()
		.filter_level(CONFIG.server.log_level)
		.parse_default_env()
		.init();
	validate_config_cache();

	info!("listening on {:?} with socket type {:?}", CONFIG.server.bind, CONFIG.server.socket);

	tokio::spawn(async {
		let mut sig = signal(SignalKind::user_defined1()).unwrap();
		while sig.recv().await.is_some() {
			info!("{}", generate_stats().unwrap());
		}
	});

	let listener = ServerListener::new().await?;
	loop {
		let (stream, id) = listener.accept().await?;
		tokio::spawn(async move {
			let stream = TokioIo::new(stream);

			let fut = Builder::new()
				.serve_connection(stream, service_fn(|req| upgrade(req, id.clone())))
				.with_upgrades();

			if let Err(e) = fut.await {
				error!("error while serving client: {:?}", e);
			}
		});
	}
}
