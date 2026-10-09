#[cfg(feature = "twisp")]
pub mod twisp;
pub mod utils;
pub mod wispnet;

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use cfg_if::cfg_if;
use event_listener::Event;
use futures_util::{future::Either, FutureExt, SinkExt, StreamExt};
use log::{debug, trace};
use tokio::{
	io::{AsyncWriteExt, BufReader},
	net::TcpStream,
	select,
	task::JoinSet,
	time::interval,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use uuid::Uuid;
use wisp_mux::{
	packet::{CloseReason, ConnectPacket},
	stream::MuxStream,
	timer::TokioTimer,
	ServerMux,
};
use wispnet::route_wispnet;

use crate::{
	route::{WispResult, WispStreamWrite, WispWsStreamWrite},
	stream::{ClientStream, ResolvedPacket},
	CLIENTS, CONFIG,
};

async fn copy_fast(
	mux: MuxStream<WispStreamWrite>,
	tcp: TcpStream,
	#[cfg(feature = "speed-limit")] read_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
	#[cfg(feature = "speed-limit")] write_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) -> std::io::Result<()> {
	let (muxrx, muxtx) = mux.into_async_rw().into_split();
	let mut muxrx = muxrx.compat();
	let mut muxtx = muxtx.compat_write();

	let (tcprx, tcptx) = tcp.into_split();

	#[cfg(feature = "speed-limit")]
	let tcprx = read_limit.limit(tcprx);
	#[cfg(feature = "speed-limit")]
	let mut tcptx = write_limit.limit(tcptx);
	#[cfg(not(feature = "speed-limit"))]
	let mut tcptx = tcptx;

	let mut tcprx = BufReader::with_capacity(CONFIG.stream.buffer_size, tcprx);

	select! {
		x = tokio::io::copy_buf(&mut muxrx, &mut tcptx) => x?,
		x = tokio::io::copy(&mut tcprx, &mut muxtx) => x?,
	};

	Ok(())
}

async fn resolve_stream(
	connect: ConnectPacket,
	muxstream: &MuxStream<WispStreamWrite>,
) -> Option<(ConnectPacket, ConnectPacket, ClientStream)> {
	let requested_stream = connect.clone();

	let Ok(resolved) = ClientStream::resolve(connect).await else {
		let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
		return None;
	};
	let (stream, resolved_stream) = match resolved {
		ResolvedPacket::Valid(connect) => {
			let resolved = connect.clone();
			let Ok(stream) = ClientStream::connect(connect).await else {
				let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
				return None;
			};
			(stream, resolved)
		}
		ResolvedPacket::ValidWispnet(server, connect) => {
			let resolved = connect.clone();
			let Ok(stream) = route_wispnet(server, connect).await else {
				let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
				return None;
			};
			(stream, resolved)
		}
		ResolvedPacket::NoResolvedAddrs => {
			let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
			return None;
		}
		ResolvedPacket::Blocked => {
			let _ = muxstream
				.close(CloseReason::ServerStreamBlockedAddress)
				.await;
			return None;
		}
		ResolvedPacket::Invalid => {
			let _ = muxstream.close(CloseReason::ServerStreamInvalidInfo).await;
			return None;
		}
	};

	Some((requested_stream, resolved_stream, stream))
}

async fn forward_stream(
	muxstream: MuxStream<WispStreamWrite>,
	stream: ClientStream,
	resolved_stream: ConnectPacket,
	uuid: Uuid,
	#[cfg(feature = "twisp")] twisp_map: twisp::TwispMap,
	#[cfg(feature = "speed-limit")] read_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
	#[cfg(feature = "speed-limit")] write_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) {
	match stream {
		ClientStream::Tcp(stream) => {
			let closer = muxstream.get_close_handle();

			let ret: anyhow::Result<()> = async {
				copy_fast(
					muxstream,
					stream,
					#[cfg(feature = "speed-limit")]
					read_limit,
					#[cfg(feature = "speed-limit")]
					write_limit,
				)
				.await?;
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
			let (mut read, write) = muxstream.into_split();
			let mut write = write.into_async_write().compat_write();

			let ret: anyhow::Result<()> = async move {
				let mut data = vec![0u8; 65507];
				loop {
					select! {
						size = stream.recv(&mut data) => {
							let size = size?;
							write.write_all(&data[..size]).await?;
						}
						data = read.next() => {
							if let Some(data) = data.transpose()? {
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
		ClientStream::UdpSocks5(stream, target) => {
			let closer = muxstream.get_close_handle();
			let (mut read, write) = muxstream.into_split();
			let mut write = write.into_async_write().compat_write();

			let ret: anyhow::Result<()> = async move {
				let mut data = vec![0u8; 65507];
				loop {
					select! {
						size = stream.recv_from(&mut data) => {
							let (size, new_target) = size?;
							if new_target != target {
								bail!("target changed while forwarding udp to {target} over socks5");
							}
							write.write_all(&data[..size]).await?;
						}
						data = read.next() => {
							if let Some(data) = data.transpose()? {
								stream.send_to(&data, target.clone()).await?;
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
			let id = muxstream.get_stream_id();
			let (mut rx, mut tx) = muxstream.into_async_rw().into_split();

			match twisp::handle_twisp(id, &mut rx, &mut tx, twisp_map.clone(), pty, cmd).await {
				Ok(()) => {
					let _ = closer.close(CloseReason::Voluntary).await;
				}
				Err(_) => {
					let _ = closer.close(CloseReason::Unexpected).await;
				}
			}
		}
		ClientStream::Wispnet(stream, mux_id) => {
			Box::pin(wispnet::handle_stream(
				muxstream,
				stream,
				mux_id,
				uuid,
				resolved_stream,
				#[cfg(feature = "speed-limit")]
				read_limit,
				#[cfg(feature = "speed-limit")]
				write_limit,
			))
			.await;
		}
		ClientStream::NoResolvedAddrs => {
			let _ = muxstream.close(CloseReason::ServerStreamUnreachable).await;
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

async fn handle_stream(
	connect: ConnectPacket,
	muxstream: MuxStream<WispStreamWrite>,
	id: String,
	event: Arc<Event>,
	#[cfg(feature = "twisp")] twisp_map: twisp::TwispMap,
	#[cfg(feature = "speed-limit")] read_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
	#[cfg(feature = "speed-limit")] write_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) {
	let Some((requested_stream, resolved_stream, stream)) =
		resolve_stream(connect, &muxstream).await
	else {
		// muxstream was closed
		return;
	};

	let uuid = Uuid::new_v4();

	debug!(
		"new stream created for client id {:?}: (stream uuid {:?}) {:?} {:?}",
		id, uuid, requested_stream, resolved_stream
	);

	if let Some(client) = CLIENTS.lock().await.get(&id) {
		client
			.0
			.lock()
			.await
			.insert(uuid, (requested_stream, resolved_stream.clone()));
	}

	let forward_fut = forward_stream(
		muxstream,
		stream,
		resolved_stream,
		uuid,
		#[cfg(feature = "twisp")]
		twisp_map,
		#[cfg(feature = "speed-limit")]
		read_limit,
		#[cfg(feature = "speed-limit")]
		write_limit,
	);

	select! {
		x = forward_fut => x,
		x = event.listen() => x,
	};

	debug!("stream uuid {:?} disconnected for client id {:?}", uuid, id);

	if let Some(client) = CLIENTS.lock().await.get(&id) {
		client.0.lock().await.remove(&uuid);
	}
}

pub async fn handle_wisp(stream: WispResult, is_v2: bool, id: String) -> anyhow::Result<()> {
	let (read, write) = stream;
	cfg_if! {
		if #[cfg(feature = "twisp")] {
			let twisp_map = twisp::new_map();
			let (extensions, required, buffer_size) = CONFIG.wisp.to_opts().await?;

			let extensions = extensions.map(|x| x.with_extension(twisp::new_ext(twisp_map.clone())));
		} else {
			let (extensions, required, buffer_size) = CONFIG.wisp.to_opts().await?;
		}
	}

	#[cfg(feature = "speed-limit")]
	let read_limiter = async_speed_limit::Limiter::builder(CONFIG.wisp.read_limit)
		.refill(Duration::from_secs(1))
		.clock(async_speed_limit::clock::StandardClock)
		.build();
	#[cfg(feature = "speed-limit")]
	let write_limiter = async_speed_limit::Limiter::builder(CONFIG.wisp.write_limit)
		.refill(Duration::from_secs(1))
		.clock(async_speed_limit::clock::StandardClock)
		.build();

	let (mux, fut) = if let Some(timeout) = CONFIG.wisp.handshake_timeout {
		Box::pin(ServerMux::with_timeout(
			read,
			write,
			TokioTimer,
			Duration::from_secs(timeout),
			buffer_size,
			if is_v2 { extensions } else { None },
			required,
		))
		.await
	} else {
		Box::pin(ServerMux::new(
			read,
			write,
			buffer_size,
			if is_v2 { extensions } else { None },
			required,
		))
		.await
	}
	.context("failed to create server multiplexor")?;
	let mux = Arc::new(mux);

	debug!(
		"new wisp client id {:?} connected with extensions {:?}, downgraded {:?}",
		id,
		mux.get_extension_ids(),
		mux.was_downgraded()
	);

	let mut set: JoinSet<()> = JoinSet::new();
	let event: Arc<Event> = Event::new().into();

	let mux_id = id.clone();
	set.spawn(fut.map(move |x| debug!("wisp client id {:?} multiplexor result {:?}", mux_id, x)));

	let ping_mux = mux.clone();
	let ping_event = event.clone();
	let ping_id = id.clone();
	set.spawn(async move {
		let mut interval = interval(Duration::from_secs(30));
		let send_ping = || async {
			let mut locked = ping_mux.lock_ws().await?;
			if let Either::Left(ws) = &mut *locked {
				<WispWsStreamWrite as SinkExt<tokio_websockets::Message>>::send(
					ws,
					tokio_websockets::Message::ping(&[] as &[u8]),
				)
				.await?;
			}
			anyhow::Ok(())
		};

		while (send_ping)().await.is_ok() {
			trace!("sent ping to wisp client id {:?}", ping_id);
			select! {
				_ = interval.tick() => (),
				() = ping_event.listen() => break,
			};
		}
	});

	while let Some((connect, stream)) = mux.wait_for_stream().await {
		set.spawn(handle_stream(
			connect,
			stream,
			id.clone(),
			event.clone(),
			#[cfg(feature = "twisp")]
			twisp_map.clone(),
			#[cfg(feature = "speed-limit")]
			read_limiter.clone(),
			#[cfg(feature = "speed-limit")]
			write_limiter.clone(),
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
