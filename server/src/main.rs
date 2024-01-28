#![feature(let_chains)]
use std::io::Error;

use bytes::Bytes;
use fastwebsockets::{
    upgrade, CloseCode, FragmentCollector, FragmentCollectorRead, Frame, OpCode, Payload,
    WebSocketError,
};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use hyper::{
    body::Incoming, header::HeaderValue, server::conn::http1, service::service_fn, Request,
    Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{native_tls, TlsAcceptor};
use tokio_util::codec::{BytesCodec, Framed};

use wisp_mux::{ws, ConnectPacket, MuxStream, Packet, ServerMux, StreamType, WispError, WsEvent};

type HttpBody = http_body_util::Empty<hyper::body::Bytes>;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let pem = include_bytes!("./pem.pem");
    let key = include_bytes!("./key.pem");
    let identity = native_tls::Identity::from_pkcs8(pem, key).expect("failed to make identity");
    let prefix = if let Some(prefix) = std::env::args().nth(1) {
        prefix
    } else {
        "/".to_string()
    };
    let port = if let Some(prefix) = std::env::args().nth(1) {
        prefix
    } else {
        "4000".to_string()
    };

    let socket = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("failed to bind");
    let acceptor = TlsAcceptor::from(
        native_tls::TlsAcceptor::new(identity).expect("failed to make tls acceptor"),
    );
    let acceptor = std::sync::Arc::new(acceptor);

    println!("listening on 0.0.0.0:4000");
    while let Ok((stream, addr)) = socket.accept().await {
        let acceptor_cloned = acceptor.clone();
        let prefix_cloned = prefix.clone();
        tokio::spawn(async move {
            let stream = acceptor_cloned.accept(stream).await.expect("not tls");
            let io = TokioIo::new(stream);
            let service =
                service_fn(move |res| accept_http(res, addr.to_string(), prefix_cloned.clone()));
            let conn = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades();
            if let Err(err) = conn.await {
                println!("{:?}: failed to serve conn: {:?}", addr, err);
            }
        });
    }

    Ok(())
}

async fn accept_http(
    mut req: Request<Incoming>,
    addr: String,
    prefix: String,
) -> Result<Response<HttpBody>, WebSocketError> {
    if upgrade::is_upgrade_request(&req)
        && req.uri().path().to_string().starts_with(&prefix)
        && let Some(protocol) = req.headers().get("Sec-Websocket-Protocol")
        && protocol == "wisp-v1"
    {
        let uri = req.uri().clone();
        let (mut res, fut) = upgrade::upgrade(&mut req)?;

        if *uri.path() != prefix {
            tokio::spawn(async move {
                accept_wsproxy(fut, uri.path().strip_prefix(&prefix).unwrap(), addr.clone()).await
            });
        } else {
            tokio::spawn(async move { accept_ws(fut, addr.clone()).await });
        }

        res.headers_mut().insert(
            "Sec-Websocket-Protocol",
            HeaderValue::from_str("wisp-v1").unwrap(),
        );
        Ok(res)
    } else {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(HttpBody::new())
            .unwrap())
    }
}

async fn handle_mux(
    packet: ConnectPacket,
    mut stream: MuxStream<impl ws::WebSocketWrite>,
) -> Result<(), WispError> {
    let uri = format!(
        "{}:{}",
        packet.destination_hostname, packet.destination_port
    );
    match packet.stream_type {
        StreamType::Tcp => {
            let tcp_stream = TcpStream::connect(uri)
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?;
            let mut tcp_stream_framed = Framed::new(tcp_stream, BytesCodec::new());

            loop {
                tokio::select! {
                    event = stream.read() => {
                        match event {
                            Some(event) => match event {
                                WsEvent::Send(data) => {
                                    tcp_stream_framed.send(data).await.map_err(|x| WispError::Other(Box::new(x)))?;
                                }
                                WsEvent::Close(_) => break,
                            },
                            None => break
                        }
                    },
                    event = tcp_stream_framed.next() => {
                        match event.and_then(|x| x.ok()) {
                            Some(event) => stream.write(event.into()).await?,
                            None => break
                        }
                    }
                }
            }
        }
        StreamType::Udp => todo!(),
    }
    Ok(())
}

async fn accept_ws(
    fut: upgrade::UpgradeFut,
    addr: String,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (rx, tx) = fut.await?.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    println!("{:?}: connected", addr);

    let mut mux = ServerMux::new(rx, tx);

    mux.server_loop(&mut |packet, stream| async move {
        let tx_cloned = stream.get_write_half();
        let stream_id = stream.stream_id;
        tokio::spawn(async move {
            let _ = handle_mux(packet, stream)
                .or_else(|err| async {
                    let _ = tx_cloned
                        .write_frame(ws::Frame::from(Packet::new_close(stream_id, 0x03)))
                        .await;
                    Err(err)
                })
                .and_then(|_| async {
                    tx_cloned
                        .write_frame(ws::Frame::from(Packet::new_close(stream_id, 0x02)))
                        .await
                })
                .await;
        });
        Ok(())
    })
    .await?;

    println!("{:?}: disconnected", addr);
    Ok(())
}

async fn accept_wsproxy(
    fut: upgrade::UpgradeFut,
    incoming_uri: &str,
    addr: String,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let mut ws_stream = FragmentCollector::new(fut.await?);

    println!("{:?}: connected (wsproxy)", addr);

    let tcp_stream = match TcpStream::connect(incoming_uri).await {
        Ok(stream) => stream,
        Err(err) => {
            ws_stream
                .write_frame(Frame::close(CloseCode::Away.into(), b"failed to connect"))
                .await
                .unwrap();
            return Err(Box::new(err));
        }
    };
    let mut tcp_stream_framed = Framed::new(tcp_stream, BytesCodec::new());

    loop {
        tokio::select! {
            event = ws_stream.read_frame() => {
                match event {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Text | OpCode::Binary => {
                                let _ = tcp_stream_framed.send(Bytes::from(frame.payload.to_vec())).await;
                            }
                            OpCode::Close => {
                                // tokio closes the stream for us
                                drop(tcp_stream_framed);
                                break;
                            }
                            _ => {}
                        }
                    },
                    Err(_) => {
                        // tokio closes the stream for us
                        drop(tcp_stream_framed);
                        break;
                    }
                }
            },
            event = tcp_stream_framed.next() => {
                if let Some(res) = event {
                    match res {
                        Ok(buf) => {
                            let _ = ws_stream.write_frame(Frame::binary(Payload::Borrowed(&buf))).await;
                        }
                        Err(_) => {
                            let _ = ws_stream.write_frame(Frame::close(CloseCode::Away.into(), b"tcp side is going away")).await;
                        }
                    }
                }
            }
        }
    }

    println!("{:?}: disconnected (wsproxy)", addr);

    Ok(())
}
