use std::collections::HashMap;

use serde::Serialize;
use wisp_mux::{ConnectPacket, StreamType};

use crate::{CLIENTS, CONFIG};

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

pub fn generate_stats() -> anyhow::Result<String> {
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
