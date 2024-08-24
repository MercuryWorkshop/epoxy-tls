use std::{
	collections::HashMap,
	os::fd::{AsRawFd, RawFd},
	sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use pty_process::{Pty, Size};
use tokio::{io::copy, process::Child, select, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use wisp_mux::{
	extensions::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder},
	ws::{LockedWebSocketWrite, WebSocketRead},
	MuxStreamAsyncRead, MuxStreamAsyncWrite, WispError,
};

pub type TwispMap = Arc<Mutex<HashMap<u32, RawFd>>>;

pub const STREAM_TYPE: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct TWispServerProtocolExtension(TwispMap);

impl TWispServerProtocolExtension {
	const ID: u8 = 0xF0;
}

#[async_trait]
impl ProtocolExtension for TWispServerProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		// Resize PTY
		&[0xF0]
	}

	fn encode(&self) -> Bytes {
		Bytes::new()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> std::result::Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		mut packet: Bytes,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> std::result::Result<(), WispError> {
		if packet.remaining() < 4 + 2 + 2 {
			return Err(WispError::PacketTooSmall);
		}
		let stream_id = packet.get_u32_le();
		let row = packet.get_u16_le();
		let col = packet.get_u16_le();

		if let Some(pty) = self.0.lock().await.get(&stream_id) {
			let _ = set_term_size(*pty, Size::new(row, col));
		}
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(self.clone())
	}
}

impl From<TWispServerProtocolExtension> for AnyProtocolExtension {
	fn from(value: TWispServerProtocolExtension) -> Self {
		AnyProtocolExtension::new(value)
	}
}

pub struct TWispServerProtocolExtensionBuilder(TwispMap);

impl ProtocolExtensionBuilder for TWispServerProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		TWispServerProtocolExtension::ID
	}

	fn build_from_bytes(
		&self,
		_: Bytes,
		_: wisp_mux::Role,
	) -> std::result::Result<AnyProtocolExtension, WispError> {
		Ok(TWispServerProtocolExtension(self.0.clone()).into())
	}

	fn build_to_extension(&self, _: wisp_mux::Role) -> AnyProtocolExtension {
		TWispServerProtocolExtension(self.0.clone()).into()
	}
}

fn set_term_size(fd: RawFd, size: Size) -> anyhow::Result<()> {
	let size = libc::winsize::from(size);
	let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, std::ptr::addr_of!(size)) };
	if ret == -1 {
		Err(rustix::io::Errno::from_raw_os_error(
			std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
		)
		.into())
	} else {
		Ok(())
	}
}

pub fn new_map() -> TwispMap {
	Arc::new(Mutex::new(HashMap::new()))
}

pub fn new_ext(map: TwispMap) -> Box<dyn ProtocolExtensionBuilder + Send + Sync> {
	Box::new(TWispServerProtocolExtensionBuilder(map))
}

pub async fn handle_twisp(
	id: u32,
	streamrx: &mut MuxStreamAsyncRead,
	streamtx: &mut MuxStreamAsyncWrite,
	map: TwispMap,
	mut pty: Pty,
	mut cmd: Child,
) -> anyhow::Result<()> {
	map.lock().await.insert(id, pty.as_raw_fd());
	let ret = async {
		let (mut ptyrx, mut ptytx) = pty.split();
		let mut streamrx = streamrx.compat();
		let mut streamtx = streamtx.compat_write();

		select! {
			x = copy(&mut ptyrx, &mut streamtx) => x.map(|_| {}),
			x = copy(&mut streamrx, &mut ptytx) => x.map(|_| {}),
			x = cmd.wait() => x.map(|_| {}),
		}?;
		Ok(())
	}
	.await;
	map.lock().await.remove(&id);
	let _ = cmd.kill().await;
	ret
}
