use std::{
	collections::HashMap,
	net::{IpAddr, SocketAddr, ToSocketAddrs},
	ops::RangeInclusive,
	path::PathBuf,
};

use anyhow::bail;
use cfg_if::cfg_if;
use clap::{Parser, ValueEnum};
use lazy_static::lazy_static;
use log::LevelFilter;
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use wisp_mux::{
	extensions::{
		cert::{CertAuthProtocolExtension, CertAuthProtocolExtensionBuilder},
		motd::MotdProtocolExtensionBuilder,
		password::{PasswordProtocolExtension, PasswordProtocolExtensionBuilder},
		udp::UdpProtocolExtensionBuilder,
		AnyProtocolExtensionBuilder,
	},
	WispV2Handshake,
};

use crate::{handle::wisp::utils::get_certificates_from_paths, CLI, CONFIG, RESOLVER};

pub const VERSION_STRING: &str = concat!(
	"git ",
	env!("VERGEN_GIT_SHA"),
	", dirty ",
	env!("VERGEN_GIT_DIRTY"),
	", compiled with rustc ",
	env!("VERGEN_RUSTC_SEMVER"),
	" on ",
	env!("VERGEN_RUSTC_HOST_TRIPLE")
);

#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SocketType {
	/// TCP socket listener.
	#[default]
	Tcp,
	/// TCP socket listener with TLS.
	TlsTcp,
	/// Unix socket listener.
	Unix,
	/// Unix socket listener with TLS.
	TlsUnix,
	/// File "socket" "listener".
	/// "Accepts" a "connection" immediately.
	File,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SocketTransport {
	/// WebSocket transport.
	#[default]
	WebSocket,
	/// Little-endian u32 length-delimited codec. See
	/// [tokio-util](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html)
	/// for more information.
	LengthDelimitedLe,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeFlavor {
	/// Single-threaded tokio runtime.
	SingleThread,
	/// Multi-threaded tokio runtime.
	#[default]
	MultiThread,
	/// Alternate multi-threaded tokio runtime.
	#[cfg(tokio_unstable)]
	MultiThreadAlt,
	/// Thread-per-core tokio runtimes.
	ThreadPerCore,
}

impl RuntimeFlavor {
	pub fn is_thread_per_core(&self) -> bool {
		match self {
			Self::ThreadPerCore => true,
			_ => false,
		}
	}
}

pub type BindAddr = (SocketType, String);

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum StatsEndpoint {
	/// Stats on the same listener as the Wisp server.
	SameServer(String),
	/// Stats on this address and socket type.
	SeparateServer(BindAddr),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
	/// Address and socket type to listen on.
	pub bind: BindAddr,
	/// Transport to listen on.
	pub transport: SocketTransport,
	/// Whether or not to resolve and connect to IPV6 upstream addresses.
	pub resolve_ipv6: bool,
	/// Whether or not to enable TCP nodelay on client TCP streams.
	pub tcp_nodelay: bool,
	/// Whether or not to set "raw mode" for the file.
	pub file_raw_mode: bool,
	/// Keypair (public, private) in PEM format for TLS.
	pub tls_keypair: Option<[PathBuf; 2]>,

	/// Where to listen for stats requests over HTTP.
	pub stats_endpoint: Option<StatsEndpoint>,

	/// Whether or not to search for the x-real-ip or x-forwarded-for headers.
	pub use_real_ip_headers: bool,
	/// String sent to a request that is not a websocket upgrade request.
	pub non_ws_response: String,

	/// Max WebSocket message size that can be recieved.
	pub max_message_size: usize,

	/// Server log level.
	pub log_level: LevelFilter,
	/// Runtime type.
	pub runtime: RuntimeFlavor,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolExtension {
	/// Wisp version 2 UDP protocol extension.
	Udp,
	/// Wisp version 2 MOTD protocol extension.
	Motd,
	/// Unofficial Wispnet-like protocol extension.
	Wispnet,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolExtensionAuth {
	/// Wisp version 2 password authentication protocol extension.
	Password,
	/// Wisp version 2 certificate authentication protocol extension.
	Certificate,
}

#[doc(hidden)]
fn default_motd() -> String {
	format!("epoxy_server ({VERSION_STRING})")
}

#[doc(hidden)]
fn is_default_motd(str: &String) -> bool {
	*str == default_motd()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WispConfig {
	/// Allow legacy wsproxy connections.
	pub allow_wsproxy: bool,
	/// Buffer size advertised to the client.
	pub buffer_size: u32,
	/// Prefix of Wisp server. Do NOT add a trailing slash here.
	pub prefix: String,

	/// Whether or not to use Wisp version 2.
	pub wisp_v2: bool,
	/// Wisp version 2 extensions advertised.
	pub extensions: Vec<ProtocolExtension>,
	/// Wisp version 2 authentication extension advertised.
	pub auth_extension: Option<ProtocolExtensionAuth>,

	/// Handshake timeout length in seconds
	pub handshake_timeout: Option<u64>,

	#[cfg(feature = "speed-limit")]
	/// Read limit in bytes/second for all streams in a wisp connection.
	pub read_limit: f64,
	#[cfg(feature = "speed-limit")]
	/// Write limit in bytes/second for all streams in a wisp connection.
	pub write_limit: f64,

	#[serde(skip_serializing_if = "HashMap::is_empty")]
	/// Wisp version 2 password authentication extension username/passwords.
	pub password_extension_users: HashMap<String, String>,
	pub password_extension_required: bool,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	/// Wisp version 2 certificate authentication extension public ed25519 pem keys.
	pub certificate_extension_keys: Vec<PathBuf>,
	pub certificate_extension_required: bool,

	#[serde(skip_serializing_if = "is_default_motd")]
	/// Wisp version 2 MOTD extension message.
	pub motd_extension: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamConfig {
	/// Whether or not to enable TCP nodelay.
	pub tcp_nodelay: bool,
	/// Buffer size of reads from TCP sockets.
	pub buffer_size: usize,

	/// Whether or not to allow Wisp clients to create UDP streams.
	pub allow_udp: bool,
	/// Whether or not to enable nonstandard legacy wsproxy UDP streams.
	pub allow_wsproxy_udp: bool,
	/// Whether or not to allow `TWisp` streams.
	#[cfg(feature = "twisp")]
	pub allow_twisp: bool,

	/// DNS servers to resolve with. Will default to system configuration.
	pub dns_servers: Vec<IpAddr>,
	/// Socks5 server to use as a proxy for streams. Currently requires a server with authentication
	/// disabled. Epoxy still does its own DNS resolution too.
	pub socks5_server: Option<String>,

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

	/// Regex whitelist of hosts for TCP connections.
	pub allow_tcp_hosts: Vec<String>,
	/// Regex blacklist of hosts for TCP connections.
	pub block_tcp_hosts: Vec<String>,

	/// Regex whitelist of hosts for UDP connections.
	pub allow_udp_hosts: Vec<String>,
	/// Regex blacklist of hosts for UDP connections.
	pub block_udp_hosts: Vec<String>,

	/// Regex whitelist of hosts.
	pub allow_hosts: Vec<String>,
	/// Regex blacklist of hosts.
	pub block_hosts: Vec<String>,

	/// Range whitelist of ports. Format is `[lower_bound, upper_bound]`.
	pub allow_ports: Vec<Vec<u16>>,
	/// Range blacklist of ports. Format is `[lower_bound, upper_bound]`.
	pub block_ports: Vec<Vec<u16>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
	/// Server-specific config.
	pub server: ServerConfig,
	/// Wisp-specific configuration.
	pub wisp: WispConfig,
	/// Individual stream-specific configuration.
	pub stream: StreamConfig,
}

#[doc(hidden)]
#[derive(Debug)]
struct ConfigCache {
	pub blocked_ports: Vec<RangeInclusive<u16>>,
	pub allowed_ports: Vec<RangeInclusive<u16>>,

	pub allowed_hosts: RegexSet,
	pub blocked_hosts: RegexSet,

	pub allowed_tcp_hosts: RegexSet,
	pub blocked_tcp_hosts: RegexSet,

	pub allowed_udp_hosts: RegexSet,
	pub blocked_udp_hosts: RegexSet,

	pub socks5_server: Option<SocketAddr>,
}

lazy_static! {
	#[doc(hidden)]
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

			allowed_tcp_hosts: RegexSet::new(&CONFIG.stream.allow_tcp_hosts).unwrap(),
			blocked_tcp_hosts: RegexSet::new(&CONFIG.stream.block_tcp_hosts).unwrap(),

			allowed_udp_hosts: RegexSet::new(&CONFIG.stream.allow_udp_hosts).unwrap(),
			blocked_udp_hosts: RegexSet::new(&CONFIG.stream.block_udp_hosts).unwrap(),

			socks5_server: CONFIG.stream.socks5_server.as_ref().map(|x| x.to_socket_addrs().expect("failed to resolve socks5 server").next().expect("failed to resolve socks5 server")),
		}
	};
}

#[doc(hidden)]
pub async fn validate_config_cache() {
	// constructs regexes
	let _ = CONFIG_CACHE.allowed_ports;
	// validates wisp config
	CONFIG.wisp.to_opts().await.unwrap();
	// constructs resolver
	RESOLVER.clear_cache();
}

impl StatsEndpoint {
	pub fn get_endpoint(&self) -> Option<String> {
		match self {
			Self::SameServer(x) => Some(x.clone()),
			Self::SeparateServer(_) => None,
		}
	}

	pub fn get_bindaddr(&self) -> Option<BindAddr> {
		match self {
			Self::SameServer(_) => None,
			Self::SeparateServer(x) => Some(x.clone()),
		}
	}
}

impl Default for ServerConfig {
	fn default() -> Self {
		Self {
			bind: (SocketType::default(), "127.0.0.1:4000".to_string()),
			transport: SocketTransport::default(),
			resolve_ipv6: false,
			tcp_nodelay: true,
			file_raw_mode: false,
			tls_keypair: None,

			stats_endpoint: None,

			use_real_ip_headers: false,
			non_ws_response: ":3".to_string(),

			max_message_size: 64 * 1024,

			log_level: LevelFilter::Info,
			runtime: RuntimeFlavor::default(),
		}
	}
}

impl Default for WispConfig {
	fn default() -> Self {
		Self {
			buffer_size: 128,
			allow_wsproxy: true,
			prefix: String::new(),

			handshake_timeout: None,

			#[cfg(feature = "speed-limit")]
			read_limit: f64::INFINITY,
			#[cfg(feature = "speed-limit")]
			write_limit: f64::INFINITY,

			wisp_v2: true,
			extensions: vec![ProtocolExtension::Udp, ProtocolExtension::Motd],
			auth_extension: None,

			password_extension_users: HashMap::new(),
			password_extension_required: true,
			certificate_extension_keys: Vec::new(),
			certificate_extension_required: true,

			motd_extension: default_motd(),
		}
	}
}

impl WispConfig {
	#[doc(hidden)]
	pub fn has_wispnet(&self) -> bool {
		self.extensions.contains(&ProtocolExtension::Wispnet)
	}

	#[doc(hidden)]
	pub async fn to_opts(&self) -> anyhow::Result<(Option<WispV2Handshake>, Vec<u8>, u32)> {
		if self.wisp_v2 {
			let mut extensions: Vec<AnyProtocolExtensionBuilder> = Vec::new();
			let mut required_extensions: Vec<u8> = Vec::new();

			if self.extensions.contains(&ProtocolExtension::Udp) {
				extensions.push(AnyProtocolExtensionBuilder::new(
					UdpProtocolExtensionBuilder,
				));
			}

			if self.extensions.contains(&ProtocolExtension::Motd) {
				extensions.push(AnyProtocolExtensionBuilder::new(
					MotdProtocolExtensionBuilder::Server(self.motd_extension.clone()),
				));
			}

			match self.auth_extension {
				Some(ProtocolExtensionAuth::Password) => {
					extensions.push(AnyProtocolExtensionBuilder::new(
						PasswordProtocolExtensionBuilder::new_server(
							self.password_extension_users.clone(),
							self.password_extension_required,
						),
					));
					if self.password_extension_required {
						required_extensions.push(PasswordProtocolExtension::ID);
					}
				}
				Some(ProtocolExtensionAuth::Certificate) => {
					extensions.push(AnyProtocolExtensionBuilder::new(
						CertAuthProtocolExtensionBuilder::new_server(
							get_certificates_from_paths(self.certificate_extension_keys.clone())
								.await?,
							self.certificate_extension_required,
						),
					));
					if self.certificate_extension_required {
						required_extensions.push(CertAuthProtocolExtension::ID);
					}
				}
				None => {}
			}

			Ok((
				Some(WispV2Handshake::new(extensions)),
				required_extensions,
				self.buffer_size,
			))
		} else {
			if self.certificate_extension_required || self.password_extension_required {
				bail!("certificate/password extension cannot be required without wisp v2");
			}

			Ok((None, vec![], self.buffer_size))
		}
	}
}

impl Default for StreamConfig {
	fn default() -> Self {
		Self {
			tcp_nodelay: true,
			buffer_size: 128 * 1024,

			allow_udp: true,
			allow_wsproxy_udp: false,
			#[cfg(feature = "twisp")]
			allow_twisp: false,

			dns_servers: Vec::new(),
			socks5_server: None,

			allow_direct_ip: true,
			allow_loopback: true,
			allow_multicast: true,

			allow_global: true,
			allow_non_global: true,

			allow_tcp_hosts: Vec::new(),
			block_tcp_hosts: Vec::new(),

			allow_udp_hosts: Vec::new(),
			block_udp_hosts: Vec::new(),

			allow_hosts: Vec::new(),
			block_hosts: Vec::new(),

			allow_ports: Vec::new(),
			block_ports: Vec::new(),
		}
	}
}

impl StreamConfig {
	#[doc(hidden)]
	pub fn socks5_server(&self) -> Option<SocketAddr> {
		CONFIG_CACHE.socks5_server
	}

	#[doc(hidden)]
	pub fn allowed_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.allowed_ports
	}

	#[doc(hidden)]
	pub fn blocked_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.blocked_ports
	}

	#[doc(hidden)]
	pub fn allowed_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.allowed_hosts
	}

	#[doc(hidden)]
	pub fn blocked_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.blocked_hosts
	}

	#[doc(hidden)]
	pub fn allowed_tcp_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.allowed_tcp_hosts
	}

	#[doc(hidden)]
	pub fn blocked_tcp_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.blocked_tcp_hosts
	}

	#[doc(hidden)]
	pub fn allowed_udp_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.allowed_udp_hosts
	}

	#[doc(hidden)]
	pub fn blocked_udp_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.blocked_udp_hosts
	}
}

impl Config {
	#[doc(hidden)]
	pub fn ser(&self) -> anyhow::Result<String> {
		Ok(match CLI.format {
			ConfigFormat::Json => serde_json::to_string_pretty(self)?,
			#[cfg(feature = "toml")]
			ConfigFormat::Toml => toml::to_string_pretty(self)?,
			#[cfg(feature = "yaml")]
			ConfigFormat::Yaml => serde_yaml::to_string(self)?,
		})
	}

	#[doc(hidden)]
	pub fn de(string: &str) -> anyhow::Result<Self> {
		Ok(match CLI.format {
			ConfigFormat::Json => serde_json::from_str(string)?,
			#[cfg(feature = "toml")]
			ConfigFormat::Toml => toml::from_str(string)?,
			#[cfg(feature = "yaml")]
			ConfigFormat::Yaml => serde_yaml::from_str(string)?,
		})
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[doc(hidden)]
pub enum ConfigFormat {
	Json,
	#[cfg(feature = "toml")]
	Toml,
	#[cfg(feature = "yaml")]
	Yaml,
}

impl Default for ConfigFormat {
	fn default() -> Self {
		cfg_if! {
			if #[cfg(feature = "toml")] {
				Self::Toml
			} else if #[cfg(feature = "yaml")] {
				Self::Yaml
			} else {
				Self::Json
			}
		}
	}
}

/// Performant server implementation of the Wisp protocol in Rust, made for epoxy.
#[doc(hidden)]
#[derive(Parser, Debug)]
#[command(version = VERSION_STRING)]
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
