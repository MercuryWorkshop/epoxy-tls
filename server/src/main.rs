#![feature(ip)]

use std::{fmt::Write, fs::read_to_string, sync::Arc};

use async_trait::async_trait;
use base64::Engine;
use bytes::BytesMut;
use clap::Parser;
use config::{validate_config_cache, Cli, Config};
use dashmap::DashMap;
use handle::handle_wisp;
use lazy_static::lazy_static;
use log::{error, info};
use tokio::{
	io::{stdin, AsyncBufReadExt, BufReader},
	signal::unix::{signal, SignalKind},
};
use uuid::Uuid;
use webrtc::{
	api::{
		interceptor_registry::register_default_interceptors, media_engine::MediaEngine, setting_engine::SettingEngine, APIBuilder
	},
	data::data_channel::DataChannel,
	data_channel::RTCDataChannel,
	ice_transport::ice_server::RTCIceServer,
	interceptor::registry::Registry,
	peer_connection::{
		configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
		sdp::session_description::RTCSessionDescription,
	},
};
use wisp_mux::{
	ws::{Frame, Payload, WebSocketRead, WebSocketWrite},
	ConnectPacket, StreamType, WispError,
};

mod config;
mod handle;
mod stream;

struct WebrtcRead(pub Arc<DataChannel>);

#[async_trait]
impl WebSocketRead for WebrtcRead {
	async fn wisp_read_frame(
		&mut self,
		_tx: &wisp_mux::ws::LockedWebSocketWrite,
	) -> Result<wisp_mux::ws::Frame<'static>, wisp_mux::WispError> {
		let mut buf = vec![0u8; 16384];
		let n = self
			.0
			.read(&mut buf)
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))?;
		Ok(Frame::binary(Payload::Bytes(buf[..n].into())))
	}
}

struct WebrtcWrite(pub Arc<DataChannel>);

#[async_trait]
impl WebSocketWrite for WebrtcWrite {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		self.0
			.write(&BytesMut::from(frame.payload).freeze())
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))?;
		Ok(())
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		self.0
			.close()
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))
	}
}

type Client = (DashMap<Uuid, (ConnectPacket, ConnectPacket)>, bool);

lazy_static! {
	pub static ref CLI: Cli = Cli::parse();
	pub static ref CONFIG: Config = {
		if let Some(path) = &CLI.config {
			Config::de(read_to_string(path).unwrap()).unwrap()
		} else {
			Config::default()
		}
	};
	pub static ref CLIENTS: DashMap<String, Client> = DashMap::new();
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
	if CLI.default_config {
		println!("{}", Config::default().ser()?);
		return Ok(());
	}

	env_logger::builder()
		.filter_level(CONFIG.server.log_level)
		.parse_default_env()
		.init();

	validate_config_cache();

	info!(
		"listening on {:?} with socket type {:?}",
		CONFIG.server.bind, CONFIG.server.socket
	);

	tokio::spawn(async {
		let mut sig = signal(SignalKind::user_defined1()).unwrap();
		while sig.recv().await.is_some() {
			info!("{}", generate_stats().unwrap());
		}
	});

	let mut media_engine = MediaEngine::default();
	media_engine.register_default_codecs()?;

	let mut registry = Registry::new();
	registry = register_default_interceptors(registry, &mut media_engine)?;

	let mut s = SettingEngine::default();
	s.detach_data_channels();

	let api = APIBuilder::new()
		.with_media_engine(media_engine)
		.with_interceptor_registry(registry)
		.with_setting_engine(s)
		.build();

	let config = RTCConfiguration {
		ice_servers: vec![RTCIceServer {
			urls: vec!["stun:stun.voip.blackberry.com:3478".to_owned()],
			..Default::default()
		}],
		..Default::default()
	};

	let peer = Arc::new(api.new_peer_connection(config).await?);

	let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(1);

	peer.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
		if s == RTCPeerConnectionState::Failed {
			done_tx.try_send(());
		}

		Box::pin(async {})
	}));

	peer.on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
		Box::pin(async move {
			let id = d.label().to_string();
			let d_inner = d.clone();
			d.on_open(Box::new(move || {
				Box::pin(async move {
					let detach = d_inner.detach().await.unwrap();
					tokio::spawn(async move {
						CLIENTS.insert(id.clone(), (DashMap::new(), false));
						if let Err(e) = handle_wisp(detach, id.clone()).await {
							error!("error while handling upgraded client {:?}: {:?}", id, e);
						};
						CLIENTS.remove(&id)
					});
				})
			}));
		})
	}));

	let mut line = String::new();
	BufReader::new(stdin()).read_line(&mut line).await;
	line = line.trim().to_string();
	let offer = serde_json::from_str::<RTCSessionDescription>(&String::from_utf8(
		base64::prelude::BASE64_STANDARD.decode(line)?,
	)?)?;

	peer.set_remote_description(offer).await?;
	let answer = peer.create_answer(None).await?;

	let mut gather_complete = peer.gathering_complete_promise().await;

	peer.set_local_description(answer).await?;

	gather_complete.recv().await;

	let json = serde_json::to_string(&peer.local_description().await.unwrap())?;
	let b64 = base64::prelude::BASE64_STANDARD.encode(json);

	println!("{:?}", b64);

	done_rx.recv().await;

	peer.close().await;

	Ok(())
}
