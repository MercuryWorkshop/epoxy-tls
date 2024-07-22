use std::{collections::HashMap, ops::RangeInclusive, path::PathBuf};

use clap::{Parser, ValueEnum};
use lazy_static::lazy_static;
use log::LevelFilter;
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use wisp_mux::extensions::{
	password::PasswordProtocolExtensionBuilder, udp::UdpProtocolExtensionBuilder,
	ProtocolExtensionBuilder,
};

use crate::{CLI, CONFIG};

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SocketType {
	/// TCP socket listener.
	#[default]
	Tcp,
	/// Unix socket listener.
	Unix,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
	/// Address to listen on.
	pub bind: String,
	/// Socket type to listen on.
	pub socket: SocketType,
	/// Whether or not to resolve and connect to IPV6 upstream addresses.
	pub resolve_ipv6: bool,
	/// Whether or not to enable TCP nodelay on client TCP streams.
	pub tcp_nodelay: bool,

	/// Whether or not to show what upstreams each client is connected to in stats. This can
	/// heavily increase the size of the stats.
	pub verbose_stats: bool,
	/// Whether or not to respond to stats requests over HTTP.
	pub enable_stats_endpoint: bool,
	/// Path of stats HTTP endpoint.
	pub stats_endpoint: String,

	/// String sent to a request that is not a websocket upgrade request.
	pub non_ws_response: String,

	/// Prefix of Wisp server. Do NOT add a trailing slash here.
	pub prefix: String,

	/// Max WebSocket message size that can be recieved.
	pub max_message_size: usize,

	/// Server log level.
	pub log_level: LevelFilter,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolExtension {
	/// Wisp draft version 2 UDP protocol extension.
	Udp,
	/// Wisp draft version 2 password protocol extension.
	Password,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct WispConfig {
	/// Allow legacy wsproxy connections.
	pub allow_wsproxy: bool,
	/// Buffer size advertised to the client.
	pub buffer_size: u32,

	/// Whether or not to use Wisp draft version 2.
	pub wisp_v2: bool,
	/// Wisp draft version 2 extensions advertised.
	pub extensions: Vec<ProtocolExtension>,
	/// Wisp draft version 2 password extension username/passwords.
	pub password_extension_users: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct StreamConfig {
	/// Whether or not to enable TCP nodelay on proxied streams.
	pub tcp_nodelay: bool,

	/// Whether or not to allow Wisp clients to create UDP streams.
	pub allow_udp: bool,
	/// Whether or not to enable nonstandard legacy wsproxy UDP streams.
	pub allow_wsproxy_udp: bool,

	/// Whether or not to allow connections to IP addresses.
	pub allow_direct_ip: bool,
	/// Whether or not to allow connections to loopback IP addresses.
	pub allow_loopback: bool,
	/// Whether or not to allow connections to multicast IP addresses.
	pub allow_multicast: bool,

	/// Whether or not to allow connections to globally-routable IP addresses.
	pub allow_global: bool,
	/// Whether or not to allow connections to non-globally-routable IP addresses.
	pub allow_non_global: bool,

	/// Regex whitelist of hosts.
	pub allow_hosts: Vec<String>,
	/// Regex blacklist of hosts.
	pub block_hosts: Vec<String>,

	/// Range whitelist of ports. Format is `[lower_bound, upper_bound]`.
	pub allow_ports: Vec<Vec<u16>>,
	/// Range blacklist of ports. Format is `[lower_bound, upper_bound]`.
	pub block_ports: Vec<Vec<u16>>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
	pub server: ServerConfig,
	pub wisp: WispConfig,
	pub stream: StreamConfig,
}

type AnyProtocolExtensionBuilder = Box<dyn ProtocolExtensionBuilder + Sync + Send>;

struct ConfigCache {
	pub blocked_ports: Vec<RangeInclusive<u16>>,
	pub allowed_ports: Vec<RangeInclusive<u16>>,

	pub allowed_hosts: RegexSet,
	pub blocked_hosts: RegexSet,

	pub wisp_config: (Option<Vec<AnyProtocolExtensionBuilder>>, u32),
}

lazy_static! {
	static ref CONFIG_CACHE: ConfigCache = {
		ConfigCache {
			allowed_ports: CONFIG
				.stream
				.allow_ports
				.iter()
				.map(|x| x[0]..=x[1])
				.collect(),
			blocked_ports: CONFIG
				.stream
				.block_ports
				.iter()
				.map(|x| x[0]..=x[1])
				.collect(),
			allowed_hosts: RegexSet::new(&CONFIG.stream.allow_hosts).unwrap(),
			blocked_hosts: RegexSet::new(&CONFIG.stream.block_hosts).unwrap(),
			wisp_config: CONFIG.wisp.to_opts_inner().unwrap(),
		}
	};
}

pub fn validate_config_cache() {
	let _ = CONFIG_CACHE.wisp_config;
}

impl Default for ServerConfig {
	fn default() -> Self {
		Self {
			bind: "127.0.0.1:4000".to_string(),
			socket: SocketType::default(),
			resolve_ipv6: false,
			tcp_nodelay: false,

			verbose_stats: true,
			stats_endpoint: "/stats".to_string(),
			enable_stats_endpoint: true,

			non_ws_response: ":3".to_string(),

			prefix: String::new(),

			max_message_size: 64 * 1024,

			log_level: LevelFilter::Info,
		}
	}
}

impl Default for WispConfig {
	fn default() -> Self {
		Self {
			buffer_size: 128,
			allow_wsproxy: true,

			wisp_v2: false,
			extensions: vec![ProtocolExtension::Udp],
			password_extension_users: HashMap::new(),
		}
	}
}

impl WispConfig {
	pub(super) fn to_opts_inner(
		&self,
	) -> anyhow::Result<(Option<Vec<AnyProtocolExtensionBuilder>>, u32)> {
		if self.wisp_v2 {
			let mut extensions: Vec<Box<dyn ProtocolExtensionBuilder + Sync + Send>> = Vec::new();

			if self.extensions.contains(&ProtocolExtension::Udp) {
				extensions.push(Box::new(UdpProtocolExtensionBuilder));
			}

			if self.extensions.contains(&ProtocolExtension::Password) {
				extensions.push(Box::new(PasswordProtocolExtensionBuilder::new_server(
					self.password_extension_users.clone(),
				)));
			}

			Ok((Some(extensions), self.buffer_size))
		} else {
			Ok((None, self.buffer_size))
		}
	}

	pub fn to_opts(&self) -> (Option<&'static [AnyProtocolExtensionBuilder]>, u32) {
		(
			CONFIG_CACHE.wisp_config.0.as_deref(),
			CONFIG_CACHE.wisp_config.1,
		)
	}
}

impl Default for StreamConfig {
	fn default() -> Self {
		Self {
			tcp_nodelay: false,

			allow_udp: true,
			allow_wsproxy_udp: false,

			allow_direct_ip: true,
			allow_loopback: true,
			allow_multicast: true,

			allow_global: true,
			allow_non_global: true,

			allow_hosts: Vec::new(),
			block_hosts: Vec::new(),

			allow_ports: Vec::new(),
			block_ports: Vec::new(),
		}
	}
}

impl StreamConfig {
	pub fn allowed_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.allowed_ports
	}

	pub fn blocked_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.blocked_ports
	}

	pub fn allowed_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.allowed_hosts
	}

	pub fn blocked_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.blocked_hosts
	}
}

impl Config {
	pub fn ser(&self) -> anyhow::Result<String> {
		Ok(match CLI.format {
			ConfigFormat::Toml => toml::to_string_pretty(self)?,
			ConfigFormat::Json => serde_json::to_string_pretty(self)?,
			ConfigFormat::Yaml => serde_yaml::to_string(self)?,
		})
	}

	pub fn de(string: String) -> anyhow::Result<Self> {
		Ok(match CLI.format {
			ConfigFormat::Toml => toml::from_str(&string)?,
			ConfigFormat::Json => serde_json::from_str(&string)?,
			ConfigFormat::Yaml => serde_yaml::from_str(&string)?,
		})
	}
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Default, ValueEnum)]
pub enum ConfigFormat {
	#[default]
	Toml,
	Json,
	Yaml,
}

/// Server implementation of the Wisp protocol in Rust, made for epoxy.
#[derive(Parser)]
#[command(version = clap::crate_version!())]
pub struct Cli {
	/// Config file to use.
	pub config: Option<PathBuf>,

	/// Config file format to use.
	#[arg(short, long, value_enum, default_value_t = ConfigFormat::default())]
	pub format: ConfigFormat,

	/// Show default config and exit.
	#[arg(long)]
	pub default_config: bool,
}
