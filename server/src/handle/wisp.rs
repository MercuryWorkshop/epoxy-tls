use anyhow::Context;
use cfg_if::cfg_if;
use futures_util::FutureExt;
use log::{debug, trace};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	net::tcp::{OwnedReadHalf, OwnedWriteHalf},
	select,
	task::JoinSet,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use uuid::Uuid;
use wisp_mux::{
	CloseReason, ConnectPacket, MuxStream, MuxStreamAsyncRead, MuxStreamWrite,
	ServerMux,
};

use crate::{
	listener::WispResult,
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
	let mut tcprx = BufReader::new(tcprx);
	loop {
		let buf = tcprx.fill_buf().await?;
		muxtx.write(&buf).await?;
		let len = buf.len();
		tcprx.consume(len);
	}
}

async fn handle_stream(
	connect: ConnectPacket,
	muxstream: MuxStream,
	id: String,
	#[cfg(feature = "twisp")] twisp_map: super::twisp::TwispMap,
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

	trace!("new stream created for client id {:?}: (stream uuid {:?}) {:?} {:?}", id, uuid, requested_stream, resolved_stream);

	CLIENTS
		.get(&id)
		.unwrap()
		.0
		.insert(uuid, (requested_stream, resolved_stream));

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

			match super::twisp::handle_twisp(id, &mut rx, &mut tx, twisp_map.clone(), pty, cmd)
				.await
			{
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

	trace!("stream uuid {:?} disconnected for client id {:?}", uuid, id);

	CLIENTS.get(&id).unwrap().0.remove(&uuid);
}

pub async fn handle_wisp(stream: WispResult, id: String) -> anyhow::Result<()> {
	let (read, write) = stream;
	cfg_if! {
		if #[cfg(feature = "twisp")] {
			let twisp_map = super::twisp::new_map();
			let (extensions, buffer_size) = CONFIG.wisp.to_opts()?;

			let extensions = match extensions {
				Some(mut exts) => {
					exts.push(super::twisp::new_ext(twisp_map.clone()));
					Some(exts)
				},
				None => {
					None
				}
			};
		} else {
			let (extensions, buffer_size) = CONFIG.wisp.to_opts()?;
		}
	}

	let (mux, fut) = ServerMux::create(read, write, buffer_size, extensions.as_deref())
		.await
		.context("failed to create server multiplexor")?
		.with_no_required_extensions();

	debug!("new wisp client id {:?} connected with extensions {:?}", id, mux.supported_extension_ids);

	let mut set: JoinSet<()> = JoinSet::new();

	set.spawn(tokio::task::unconstrained(fut.map(|_| {})));

	while let Some((connect, stream)) = mux.server_new_stream().await {
		set.spawn(tokio::task::unconstrained(handle_stream(
			connect,
			stream,
			id.clone(),
			#[cfg(feature = "twisp")]
			twisp_map.clone(),
		)));
	}

	let _ = mux.close().await;

	set.abort_all();

	while set.join_next().await.is_some() {}

	debug!("wisp client id {:?} disconnected", id);

	Ok(())
}
