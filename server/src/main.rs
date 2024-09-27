#![feature(ip)]
#![deny(clippy::todo)]

use std::{collections::HashMap, fs::read_to_string, net::IpAddr};

use anyhow::Context;
use clap::Parser;
use config::{validate_config_cache, Cli, Config};
use dashmap::DashMap;
use handle::{handle_wisp, handle_wsproxy};
use hickory_resolver::{
	config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
	TokioAsyncResolver,
};
use lazy_static::lazy_static;
use listener::ServerListener;
use log::{error, info};
use route::{route_stats, ServerRouteResult};
use serde::Serialize;
use tokio::signal::unix::{signal, SignalKind};
use uuid::Uuid;
use wisp_mux::{ConnectPacket, StreamType};

mod config;
mod handle;
mod listener;
mod route;
mod stream;

type Client = (DashMap<Uuid, (ConnectPacket, ConnectPacket)>, bool);

pub enum Resolver {
	Hickory(TokioAsyncResolver),
	System,
}

impl Resolver {
	pub async fn resolve(&self, host: String) -> anyhow::Result<Box<dyn Iterator<Item = IpAddr>>> {
		match self {
			Self::Hickory(resolver) => Ok(Box::new(resolver.lookup_ip(host).await?.into_iter())),
			Self::System => Ok(Box::new(
				tokio::net::lookup_host(host + ":0").await?.map(|x| x.ip()),
			)),
		}
	}

	pub fn clear_cache(&self) {
		match self {
			Self::Hickory(resolver) => resolver.clear_cache(),
			Self::System => {}
		}
	}
}

lazy_static! {
	pub static ref CLI: Cli = Cli::parse();
	pub static ref CONFIG: Config = {
		if let Some(path) = &CLI.config {
			Config::de(
				read_to_string(path)
					.context("failed to read config")
					.unwrap(),
			)
			.context("failed to parse config")
			.unwrap()
		} else {
			Config::default()
		}
	};
	pub static ref CLIENTS: DashMap<String, Client> = DashMap::new();
	pub static ref RESOLVER: Resolver = {
		if CONFIG.stream.dns_servers.is_empty() {
			Resolver::System
		} else {
			Resolver::Hickory(TokioAsyncResolver::tokio(
				ResolverConfig::from_parts(
					None,
					Vec::new(),
					NameServerConfigGroup::from_ips_clear(&CONFIG.stream.dns_servers, 53, true),
				),
				ResolverOpts::default(),
			))
		}
	};
}

fn format_stream_type(stream_type: StreamType) -> &'static str {
	match stream_type {
		StreamType::Tcp => "tcp",
		StreamType::Udp => "udp",
		#[cfg(feature = "twisp")]
		StreamType::Unknown(crate::handle::wisp::twisp::STREAM_TYPE) => "twisp",
		StreamType::Unknown(_) => unreachable!(),
	}
}

#[derive(Serialize)]
struct MemoryStats {
	active: f64,
	allocated: f64,
	mapped: f64,
	metadata: f64,
	resident: f64,
	retained: f64,
}

#[derive(Serialize)]
struct StreamStats {
	stream_type: String,
	requested: String,
	resolved: String,
}

impl From<(ConnectPacket, ConnectPacket)> for StreamStats {
	fn from(value: (ConnectPacket, ConnectPacket)) -> Self {
		Self {
			stream_type: format_stream_type(value.0.stream_type).to_string(),
			requested: format!(
				"{}:{}",
				value.0.destination_hostname, value.0.destination_port
			),
			resolved: format!(
				"{}:{}",
				value.1.destination_hostname, value.1.destination_port
			),
		}
	}
}

#[derive(Serialize)]
struct ClientStats {
	wsproxy: bool,
	streams: HashMap<String, StreamStats>,
}

#[derive(Serialize)]
struct ServerStats {
	config: String,
	clients: HashMap<String, ClientStats>,
	memory: MemoryStats,
}

fn generate_stats() -> anyhow::Result<String> {
	use tikv_jemalloc_ctl::stats::{active, allocated, mapped, metadata, resident, retained};
	tikv_jemalloc_ctl::epoch::advance()?;

	let memory = MemoryStats {
		active: active::read()? as f64 / (1024 * 1024) as f64,
		allocated: allocated::read()? as f64 / (1024 * 1024) as f64,
		mapped: mapped::read()? as f64 / (1024 * 1024) as f64,
		metadata: metadata::read()? as f64 / (1024 * 1024) as f64,
		resident: resident::read()? as f64 / (1024 * 1024) as f64,
		retained: retained::read()? as f64 / (1024 * 1024) as f64,
	};

	let clients = CLIENTS
		.iter()
		.map(|x| {
			(
				x.key().to_string(),
				ClientStats {
					wsproxy: x.value().1,
					streams: x
						.value()
						.0
						.iter()
						.map(|x| (x.key().to_string(), StreamStats::from(x.value().clone())))
						.collect(),
				},
			)
		})
		.collect();

	let stats = ServerStats {
		config: CONFIG.ser()?,
		clients,
		memory,
	};

	Ok(serde_json::to_string_pretty(&stats)?)
}

fn handle_stream(stream: ServerRouteResult, id: String) {
	tokio::spawn(async move {
		CLIENTS.insert(id.clone(), (DashMap::new(), false));
		let res = match stream {
			ServerRouteResult::Wisp(stream) => handle_wisp(stream, id.clone()).await,
			ServerRouteResult::WsProxy(ws, path, udp) => {
				handle_wsproxy(ws, id.clone(), path, udp).await
			}
		};
		if let Err(e) = res {
			error!("error while handling client: {:?}", e);
		}
		CLIENTS.remove(&id)
	});
}

#[global_allocator]
static JEMALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
	if CLI.default_config {
		println!("{}", Config::default().ser()?);
		return Ok(());
	}

	env_logger::builder()
		.filter_level(CONFIG.server.log_level)
		.parse_default_env()
		.init();

	validate_config_cache().await;

	info!(
		"listening on {:?} with socket transport {:?}",
		CONFIG.server.bind, CONFIG.server.transport
	);

	tokio::spawn(async {
		let mut sig = signal(SignalKind::user_defined1()).unwrap();
		while sig.recv().await.is_some() {
			info!("Stats:\n{}", generate_stats().unwrap());
		}
	});

	let mut listener = ServerListener::new(&CONFIG.server.bind)
		.await
		.with_context(|| format!("failed to bind to address {}", CONFIG.server.bind.1))?;

	if CONFIG.server.enable_stats_endpoint {
		if let Some(bind_addr) = CONFIG.server.stats_endpoint.get_bindaddr() {
			info!("stats server listening on {:?}", bind_addr);
			let mut stats_listener = ServerListener::new(&bind_addr).await.with_context(|| {
				format!("failed to bind to address {} for stats server", bind_addr.1)
			})?;

			tokio::spawn(async move {
				loop {
					match stats_listener.accept().await {
						Ok((stream, _)) => {
							if let Err(e) = route_stats(stream).await {
								error!("error while routing stats client: {:?}", e);
							}
						}
						Err(e) => error!("error while accepting stats client: {:?}", e),
					}
				}
			});
		}
	}

	let stats_endpoint = CONFIG.server.stats_endpoint.get_endpoint();
	loop {
		let stats_endpoint = stats_endpoint.clone();
		match listener.accept().await {
			Ok((stream, id)) => {
				tokio::spawn(async move {
					let res = route::route(stream, stats_endpoint, move |stream| {
						handle_stream(stream, id)
					})
					.await;

					if let Err(e) = res {
						error!("error while routing client: {:?}", e);
					}
				});
			}
			Err(e) => error!("error while accepting client: {:?}", e),
		}
	}
}
