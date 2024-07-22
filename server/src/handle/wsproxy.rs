use std::str::FromStr;

use anyhow::Context;
use fastwebsockets::{upgrade::UpgradeFut, CloseCode, FragmentCollector};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	select,
};
use uuid::Uuid;
use wisp_mux::{ConnectPacket, StreamType};

use crate::{
	stream::{ClientStream, ResolvedPacket, WebSocketFrame, WebSocketStreamWrapper},
	CLIENTS, CONFIG,
};

pub async fn handle_wsproxy(
	fut: UpgradeFut,
	id: String,
	path: String,
	udp: bool,
) -> anyhow::Result<()> {
	let mut ws = fut.await.context("failed to await upgrade future")?;
	ws.set_max_message_size(CONFIG.server.max_message_size);
	let ws = FragmentCollector::new(ws);
	let mut ws = WebSocketStreamWrapper(ws);

	if udp && !CONFIG.stream.allow_wsproxy_udp {
		let _ = ws.close(CloseCode::Error.into(), b"udp is blocked").await;
		return Ok(());
	}

	let vec: Vec<&str> = path.split("/").last().unwrap().split(":").collect();
	let Ok(port) = FromStr::from_str(vec[1]) else {
		let _ = ws.close(CloseCode::Error.into(), b"invalid port").await;
		return Ok(());
	};
	let connect = ConnectPacket {
		stream_type: if udp {
			StreamType::Udp
		} else {
			StreamType::Tcp
		},
		destination_hostname: vec[0].to_string(),
		destination_port: port,
	};

	let requested_stream = connect.clone();

	let Ok(resolved) = ClientStream::resolve(connect).await else {
		let _ = ws
			.close(CloseCode::Error.into(), b"failed to resolve host")
			.await;
		return Ok(());
	};
	let connect = match resolved {
		ResolvedPacket::Valid(x) => x,
		ResolvedPacket::NoResolvedAddrs => {
			let _ = ws
				.close(
					CloseCode::Error.into(),
					b"host did not resolve to any addrs",
				)
				.await;
			return Ok(());
		}
		ResolvedPacket::Blocked => {
			let _ = ws.close(CloseCode::Error.into(), b"host is blocked").await;
			return Ok(());
		}
	};

	let resolved_stream = connect.clone();

	let Ok(stream) = ClientStream::connect(connect).await else {
		let _ = ws
			.close(CloseCode::Error.into(), b"failed to connect to host")
			.await;
		return Ok(());
	};

	let uuid = Uuid::new_v4();

	CLIENTS
		.get(&id)
		.unwrap()
		.0
		.insert(uuid, (requested_stream, resolved_stream));

	match stream {
		ClientStream::Tcp(stream) => {
			let mut stream = BufReader::new(stream);
			let ret: anyhow::Result<()> = async {
				let mut to_consume = 0usize;
				loop {
					if to_consume != 0 {
						stream.consume(to_consume);
						to_consume = 0;
					}
					select! {
						x = ws.read() => {
							match x? {
								WebSocketFrame::Data(data) => {
									stream.write_all(&data).await?;
								}
								WebSocketFrame::Close => {
									stream.shutdown().await?;
								}
								WebSocketFrame::Ignore => {}
							}
						}
						x = stream.fill_buf() => {
							let x = x?;
							ws.write(x).await?;
							to_consume += x.len();
						}
					}
				}
			}
			.await;
			match ret {
				Ok(_) => {
					let _ = ws.close(CloseCode::Normal.into(), b"").await;
				}
				Err(x) => {
					let _ = ws
						.close(CloseCode::Normal.into(), x.to_string().as_bytes())
						.await;
				}
			}
		}
		ClientStream::Udp(_stream) => {
			// TODO
			let _ = ws.close(CloseCode::Error.into(), b"coming soon").await;
		}
		ClientStream::Blocked => {
			let _ = ws.close(CloseCode::Error.into(), b"host is blocked").await;
		}
		ClientStream::Invalid => {
			let _ = ws.close(CloseCode::Error.into(), b"host is invalid").await;
		}
	}

	Ok(())
}
