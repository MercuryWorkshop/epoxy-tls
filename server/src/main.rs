#![feature(ip)]

use std::{env::args, fs::read_to_string, ops::Deref};

use anyhow::Context;
use bytes::Bytes;
use config::{validate_config_cache, Config};
use fastwebsockets::{upgrade::UpgradeFut, FragmentCollectorRead};
use http_body_util::Empty;
use hyper::{body::Incoming, server::conn::http1::Builder, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use stream::{
	copy_read_fast, ClientStream, ResolvedPacket, ServerListener, ServerStream, ServerStreamExt,
};
use tokio::{io::copy, select};
use tokio_util::compat::FuturesAsyncWriteCompatExt;
use wisp_mux::{CloseReason, ConnectPacket, MuxStream, ServerMux};

mod config;
mod stream;

lazy_static! {
	pub static ref CONFIG: Config = {
		if let Some(path) = args().nth(1) {
			toml::from_str(&read_to_string(path).unwrap()).unwrap()
		} else {
			Config::default()
		}
	};
}

async fn handle_stream(connect: ConnectPacket, muxstream: MuxStream) {
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
	};

	let Ok(stream) = ClientStream::connect(connect).await else {
		let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
		return;
	};

	match stream {
		ClientStream::Tcp(stream) => {
			let closer = muxstream.get_close_handle();

			let ret: anyhow::Result<()> = async move {
				let (muxread, muxwrite) = muxstream.into_io().into_asyncrw().into_split();
				let (mut tcpread, tcpwrite) = stream.into_split();
				let mut muxwrite = muxwrite.compat_write();
				select! {
					x = copy_read_fast(muxread, tcpwrite) => x?,
					x = copy(&mut tcpread, &mut muxwrite) => {x?;},
				}
				// TODO why is copy_write_fast not working?
				/*
				let (muxread, muxwrite) = muxstream.into_split();
				let muxread = muxread.into_stream().into_asyncread();
				let (mut tcpread, tcpwrite) = stream.into_split();
				select! {
					x = copy_read_fast(muxread, tcpwrite) => x?,
					x = copy_write_fast(muxwrite, tcpread) => {x?;},
				}
				*/
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
}

async fn handle(fut: UpgradeFut) -> anyhow::Result<()> {
	let mut ws = fut.await.context("failed to await upgrade future")?;

	ws.set_max_message_size(CONFIG.server.max_message_size);

	let (read, write) = ws.split(|x| {
		let parts = x.into_inner().downcast::<TokioIo<ServerStream>>().unwrap();
		assert_eq!(parts.read_buf.len(), 0);
		parts.io.into_inner().split()
	});
	let read = FragmentCollectorRead::new(read);

	let (extensions, buffer_size) = CONFIG.wisp.to_opts_inner()?;

	let (mux, fut) = ServerMux::create(read, write, buffer_size, extensions.as_deref())
		.await
		.context("failed to create server multiplexor")?
		.with_no_required_extensions();

	tokio::spawn(tokio::task::unconstrained(fut));

	while let Some((connect, stream)) = mux.server_new_stream().await {
		tokio::spawn(tokio::task::unconstrained(handle_stream(connect, stream)));
	}

	Ok(())
}

type Body = Empty<Bytes>;
async fn upgrade(mut req: Request<Incoming>) -> anyhow::Result<Response<Body>> {
	let (resp, fut) = fastwebsockets::upgrade::upgrade(&mut req)?;

	tokio::spawn(async move {
		if let Err(e) = handle(fut).await {
			println!("{:?}", e);
		};
	});

	Ok(resp)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
	validate_config_cache();

	println!("{}", toml::to_string_pretty(CONFIG.deref()).unwrap());

	let listener = ServerListener::new().await?;
	loop {
		let (stream, _) = listener.accept().await?;
		tokio::spawn(async move {
			let stream = TokioIo::new(stream);

			let fut = Builder::new()
				.serve_connection(stream, service_fn(upgrade))
				.with_upgrades();

			if let Err(e) = fut.await {
				println!("{:?}", e);
			}
		});
	}
}
