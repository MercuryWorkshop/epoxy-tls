use std::io::Cursor;

use anyhow::Context;
use fastwebsockets::upgrade::UpgradeFut;
use futures_util::FutureExt;
use hyper_util::rt::TokioIo;
use tokio::{
	io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
	net::tcp::{OwnedReadHalf, OwnedWriteHalf},
	select,
	task::JoinSet,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use uuid::Uuid;
use wisp_mux::{
	CloseReason, ConnectPacket, MuxStream, MuxStreamAsyncRead, MuxStreamWrite, ServerMux,
};

use crate::{
	stream::{ClientStream, ResolvedPacket, ServerStream, ServerStreamExt},
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

async fn handle_stream(connect: ConnectPacket, muxstream: MuxStream, id: String) {
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
		ClientStream::Invalid => {
			let _ = muxstream.close(CloseReason::ServerStreamInvalidInfo).await;
		}
		ClientStream::Blocked => {
			let _ = muxstream
				.close(CloseReason::ServerStreamBlockedAddress)
				.await;
		}
	};

	CLIENTS.get(&id).unwrap().0.remove(&uuid);
}

pub async fn handle_wisp(fut: UpgradeFut, id: String) -> anyhow::Result<()> {
	let mut ws = fut.await.context("failed to await upgrade future")?;
	ws.set_max_message_size(CONFIG.server.max_message_size);

	let (read, write) = ws.split(|x| {
		let parts = x.into_inner().downcast::<TokioIo<ServerStream>>().unwrap();
		let (r, w) = parts.io.into_inner().split();
		(Cursor::new(parts.read_buf).chain(r), w)
	});

	let (extensions, buffer_size) = CONFIG.wisp.to_opts();

	let (mux, fut) = ServerMux::create(read, write, buffer_size, extensions)
		.await
		.context("failed to create server multiplexor")?
		.with_no_required_extensions();

	let mut set: JoinSet<()> = JoinSet::new();

	set.spawn(tokio::task::unconstrained(fut.map(|_| {})));

	while let Some((connect, stream)) = mux.server_new_stream().await {
		set.spawn(tokio::task::unconstrained(handle_stream(
			connect,
			stream,
			id.clone(),
		)));
	}

	set.abort_all();

	while set.join_next().await.is_some() {}

	Ok(())
}
