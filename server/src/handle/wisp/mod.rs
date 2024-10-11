#[cfg(feature = "twisp")]
pub mod twisp;
pub mod utils;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bytes::BytesMut;
use cfg_if::cfg_if;
use event_listener::Event;
use futures_util::FutureExt;
use log::{debug, trace};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	net::tcp::{OwnedReadHalf, OwnedWriteHalf},
	select,
	task::JoinSet,
	time::interval,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use uuid::Uuid;
use wisp_mux::{
	ws::Payload, CloseReason, ConnectPacket, MuxStream, MuxStreamAsyncRead, MuxStreamWrite,
	ServerMux,
};

use crate::{
	route::WispResult,
	stream::{ClientStream, ResolvedPacket},
	CLIENTS, CONFIG,
};

async fn copy_read_fast(
	muxrx: MuxStreamAsyncRead,
	mut tcptx: OwnedWriteHalf,
) -> std::io::Result<()> {
	let mut muxrx = muxrx.compat();
	loop {
		let buf = muxrx.fill_buf().await?;
		if buf.is_empty() {
			tcptx.flush().await?;
			return Ok(());
		}

		let i = tcptx.write(buf).await?;
		if i == 0 {
			return Err(std::io::ErrorKind::WriteZero.into());
		}

		muxrx.consume(i);
	}
}

async fn copy_write_fast(muxtx: MuxStreamWrite, tcprx: OwnedReadHalf) -> anyhow::Result<()> {
	let mut tcprx = BufReader::with_capacity(CONFIG.stream.buffer_size, tcprx);
	loop {
		let buf = tcprx.fill_buf().await?;

		let len = buf.len();
		if len == 0 {
			return Ok(());
		}

		muxtx.write(&buf).await?;
		tcprx.consume(len);
	}
}

async fn handle_stream(
	connect: ConnectPacket,
	muxstream: MuxStream,
	id: String,
	event: Arc<Event>,
	#[cfg(feature = "twisp")] twisp_map: twisp::TwispMap,
) {
	let requested_stream = connect.clone();

	let Ok(resolved) = ClientStream::resolve(connect).await else {
		let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
		return;
	};
	let connect = match resolved {
		ResolvedPacket::Valid(x) => x,
		ResolvedPacket::NoResolvedAddrs => {
			let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
			return;
		}
		ResolvedPacket::Blocked => {
			let _ = muxstream
				.close(CloseReason::ServerStreamBlockedAddress)
				.await;
			return;
		}
		ResolvedPacket::Invalid => {
			let _ = muxstream.close(CloseReason::ServerStreamInvalidInfo).await;
			return;
		}
	};

	let resolved_stream = connect.clone();

	let Ok(stream) = ClientStream::connect(connect).await else {
		let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
		return;
	};

	let uuid = Uuid::new_v4();

	debug!(
		"new stream created for client id {:?}: (stream uuid {:?}) {:?} {:?}",
		id, uuid, requested_stream, resolved_stream
	);

	if let Some(client) = CLIENTS.get(&id) {
		client.0.insert(uuid, (requested_stream, resolved_stream));
	}

	let forward_fut = async {
		match stream {
			ClientStream::Tcp(stream) => {
				let closer = muxstream.get_close_handle();

				let ret: anyhow::Result<()> = async {
					let (muxread, muxwrite) = muxstream.into_split();
					let muxread = muxread.into_stream().into_asyncread();
					let (tcpread, tcpwrite) = stream.into_split();
					select! {
						x = copy_read_fast(muxread, tcpwrite) => x?,
						x = copy_write_fast(muxwrite, tcpread) => x?,
					}
					Ok(())
				}
				.await;

				match ret {
					Ok(()) => {
						let _ = closer.close(CloseReason::Voluntary).await;
					}
					Err(_) => {
						let _ = closer.close(CloseReason::Unexpected).await;
					}
				}
			}
			ClientStream::Udp(stream) => {
				let closer = muxstream.get_close_handle();

				let ret: anyhow::Result<()> = async move {
					let mut data = vec![0u8; 65507];
					loop {
						select! {
							size = stream.recv(&mut data) => {
								let size = size?;
								muxstream.write(&data[..size]).await?;
							}
							data = muxstream.read() => {
								if let Some(data) = data {
									stream.send(&data).await?;
								} else {
									break Ok(());
								}
							}
						}
					}
				}
				.await;

				match ret {
					Ok(()) => {
						let _ = closer.close(CloseReason::Voluntary).await;
					}
					Err(_) => {
						let _ = closer.close(CloseReason::Unexpected).await;
					}
				}
			}
			#[cfg(feature = "twisp")]
			ClientStream::Pty(cmd, pty) => {
				let closer = muxstream.get_close_handle();
				let id = muxstream.stream_id;
				let (mut rx, mut tx) = muxstream.into_io().into_asyncrw().into_split();

				match twisp::handle_twisp(id, &mut rx, &mut tx, twisp_map.clone(), pty, cmd).await {
					Ok(()) => {
						let _ = closer.close(CloseReason::Voluntary).await;
					}
					Err(_) => {
						let _ = closer.close(CloseReason::Unexpected).await;
					}
				}
			}
			ClientStream::Invalid => {
				let _ = muxstream.close(CloseReason::ServerStreamInvalidInfo).await;
			}
			ClientStream::Blocked => {
				let _ = muxstream
					.close(CloseReason::ServerStreamBlockedAddress)
					.await;
			}
		};
	};

	select! {
		x = forward_fut => x,
		x = event.listen() => x,
	};

	debug!("stream uuid {:?} disconnected for client id {:?}", uuid, id);

	if let Some(client) = CLIENTS.get(&id) {
		client.0.remove(&uuid);
	}
}

pub async fn handle_wisp(stream: WispResult, id: String) -> anyhow::Result<()> {
	let (read, write) = stream;
	cfg_if! {
		if #[cfg(feature = "twisp")] {
			let twisp_map = twisp::new_map();
			let (extensions, required_extensions, buffer_size) = CONFIG.wisp.to_opts().await?;

			let extensions = match extensions {
				Some(mut exts) => {
					exts.add_extension(twisp::new_ext(twisp_map.clone()));
					Some(exts)
				},
				None => {
					None
				}
			};
		} else {
			let (extensions, required_extensions, buffer_size) = CONFIG.wisp.to_opts().await?;
		}
	}

	let (mux, fut) = ServerMux::create(read, write, buffer_size, extensions)
		.await
		.context("failed to create server multiplexor")?
		.with_required_extensions(&required_extensions)
		.await?;
	let mux = Arc::new(mux);

	debug!(
		"new wisp client id {:?} connected with extensions {:?}, downgraded {:?}",
		id,
		mux.supported_extensions
			.iter()
			.map(|x| x.get_id())
			.collect::<Vec<_>>(),
		mux.downgraded
	);

	let mut set: JoinSet<()> = JoinSet::new();
	let event: Arc<Event> = Event::new().into();

	let mux_id = id.clone();
	set.spawn(tokio::task::unconstrained(fut.map(move |x| {
		debug!("wisp client id {:?} multiplexor result {:?}", mux_id, x)
	})));

	let ping_mux = mux.clone();
	let ping_event = event.clone();
	let ping_id = id.clone();
	set.spawn(async move {
		let mut interval = interval(Duration::from_secs(30));
		while ping_mux
			.send_ping(Payload::Bytes(BytesMut::new()))
			.await
			.is_ok()
		{
			trace!("sent ping to wisp client id {:?}", ping_id);
			select! {
				_ = interval.tick() => (),
				_ = ping_event.listen() => break,
			};
		}
	});

	while let Some((connect, stream)) = mux.server_new_stream().await {
		set.spawn(handle_stream(
			connect,
			stream,
			id.clone(),
			event.clone(),
			#[cfg(feature = "twisp")]
			twisp_map.clone(),
		));
	}

	debug!("shutting down wisp client id {:?}", id);

	let _ = mux.close().await;
	event.notify(usize::MAX);

	trace!("waiting for tasks to close for wisp client id {:?}", id);

	while set.join_next().await.is_some() {}

	debug!("wisp client id {:?} disconnected", id);

	Ok(())
}
