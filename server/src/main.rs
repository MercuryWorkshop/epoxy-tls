#![feature(let_chains, ip)]
use std::io::Error;

use bytes::Bytes;
use clap::Parser;
use fastwebsockets::{
    upgrade, CloseCode, FragmentCollector, FragmentCollectorRead, Frame, OpCode, Payload,
    WebSocketError,
};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{BytesCodec, Framed};
#[cfg(unix)]
use tokio_util::either::Either;

use wisp_mux::{CloseReason, ConnectPacket, MuxStream, ServerMux, StreamType, WispError};

type HttpBody = http_body_util::Full<hyper::body::Bytes>;

/// Server implementation of the Wisp protocol in Rust, made for epoxy
#[derive(Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
    /// URL prefix the server should serve on
    #[arg(long, default_value = "")]
    prefix: String,
    /// Port the server should bind to
    #[arg(long, short, default_value = "4000")]
    port: String,
    /// Host the server should bind to
    #[arg(long = "host", short, value_name = "HOST", default_value = "0.0.0.0")]
    bind_host: String,
    /// Whether the server should listen on a Unix socket located at the value of the bind_host
    /// argument
    #[arg(long, short)]
    unix_socket: bool,
    /// Whether the server should block IP addresses that are not globally reachable
    ///
    /// See https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_global for which IP
    /// addresses are blocked
    #[arg(long, short = 'B')]
    block_local: bool,
}

#[cfg(not(unix))]
type ListenerStream = TcpStream;
#[cfg(unix)]
type ListenerStream = Either<TcpStream, UnixStream>;

enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    pub async fn accept(&self) -> Result<(ListenerStream, String), std::io::Error> {
        Ok(match self {
            Listener::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                #[cfg(not(unix))]
                {
                    (stream, addr.to_string())
                }
                #[cfg(unix)]
                {
                    (Either::Left(stream), addr.to_string())
                }
            }
            #[cfg(unix)]
            Listener::Unix(listener) => {
                let (stream, addr) = listener.accept().await?;
                (
                    Either::Right(stream),
                    addr.as_pathname()
                        .map(|x| x.to_string_lossy().into())
                        .unwrap_or("unknown_unix_socket".into()),
                )
            }
        })
    }
}

async fn bind(addr: &str, unix: bool) -> Result<Listener, std::io::Error> {
    #[cfg(unix)]
    if unix {
        if std::fs::metadata(addr).is_ok() {
            println!("attempting to remove old socket {:?}", addr);
            std::fs::remove_file(addr)?;
        }
        return Ok(Listener::Unix(UnixListener::bind(addr)?));
    }
    #[cfg(not(unix))]
    if unix {
        panic!("Unix sockets are only supported on Unix.");
    }

    Ok(Listener::Tcp(TcpListener::bind(addr).await?))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();
    let opt = Cli::parse();
    let addr = if opt.unix_socket {
        opt.bind_host
    } else {
        format!("{}:{}", opt.bind_host, opt.port)
    };

    let socket = bind(&addr, opt.unix_socket).await?;

    let prefix = if opt.prefix.starts_with('/') {
        opt.prefix
    } else {
        "/".to_string() + &opt.prefix
    };

    println!("listening on `{}`", addr);
    while let Ok((stream, addr)) = socket.accept().await {
        let prefix = prefix.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |res| {
                accept_http(res, addr.clone(), prefix.clone(), opt.block_local)
            });
            let conn = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades();
            if let Err(err) = conn.await {
                println!("failed to serve conn: {:?}", err);
            }
        });
    }

    Ok(())
}

async fn accept_http(
    mut req: Request<Incoming>,
    addr: String,
    prefix: String,
    block_local: bool,
) -> Result<Response<HttpBody>, WebSocketError> {
    let uri = req.uri().path().to_string();
    if upgrade::is_upgrade_request(&req)
        && let Some(uri) = uri.strip_prefix(&prefix)
    {
        let (res, fut) = upgrade::upgrade(&mut req)?;

        if uri == "/" {
            tokio::spawn(async move { accept_ws(fut, addr.clone(), block_local).await });
        } else if let Some(uri) = uri.strip_prefix('/').map(|x| x.to_string()) {
            tokio::spawn(async move { accept_wsproxy(fut, uri, addr.clone(), block_local).await });
        }

        Ok(Response::from_parts(
            res.into_parts().0,
            HttpBody::new(Bytes::new()),
        ))
    } else {
        println!("random request to path {:?}", uri);
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(HttpBody::new(":3".into()))
            .unwrap())
    }
}

async fn handle_mux(packet: ConnectPacket, mut stream: MuxStream) -> Result<bool, WispError> {
    let uri = format!(
        "{}:{}",
        packet.destination_hostname, packet.destination_port
    );
    match packet.stream_type {
        StreamType::Tcp => {
            let mut tcp_stream = TcpStream::connect(uri)
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?;
            let mut mux_stream = stream.into_io().into_asyncrw();
            tokio::io::copy_bidirectional(&mut tcp_stream, &mut mux_stream)
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?;
        }
        StreamType::Udp => {
            let uri = lookup_host(uri)
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?
                .next()
                .ok_or(WispError::InvalidUri)?;
            let udp_socket = UdpSocket::bind(if uri.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?;
            udp_socket
                .connect(uri)
                .await
                .map_err(|x| WispError::Other(Box::new(x)))?;
            let mut data = vec![0u8; 65507]; // udp standard max datagram size
            loop {
                tokio::select! {
                    size = udp_socket.recv(&mut data).map_err(|x| WispError::Other(Box::new(x))) => {
                        let size = size?;
                        stream.write(Bytes::copy_from_slice(&data[..size])).await?
                    },
                    event = stream.read() => {
                        match event {
                            Some(event) => {
                                let _ = udp_socket.send(&event).await.map_err(|x| WispError::Other(Box::new(x)))?;
                            }
                            None => break,
                        }
                    }
                }
            }
        }
    }
    Ok(true)
}

async fn accept_ws(
    fut: upgrade::UpgradeFut,
    addr: String,
    block_local: bool,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (rx, tx) = fut.await?.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    println!("{:?}: connected", addr);

    let (mut mux, fut) = ServerMux::new(rx, tx, 128);

    tokio::spawn(async move {
        if let Err(e) = fut.await {
            println!("err in mux: {:?}", e);
        }
    });

    while let Some((packet, stream)) = mux.server_new_stream().await {
        tokio::spawn(async move {
            if block_local {
                match lookup_host(format!(
                    "{}:{}",
                    packet.destination_hostname, packet.destination_port
                ))
                .await
                .ok()
                .and_then(|mut x| x.next())
                .map(|x| !x.ip().is_global())
                {
                    Some(true) => {
                        let _ = stream.close(CloseReason::ServerStreamBlockedAddress).await;
                        return;
                    }
                    Some(false) => {}
                    None => {
                        let _ = stream
                            .close(CloseReason::ServerStreamConnectionRefused)
                            .await;
                        return;
                    }
                }
            }
            let close_err = stream.get_close_handle();
            let close_ok = stream.get_close_handle();
            let _ = handle_mux(packet, stream)
                .or_else(|err| async move {
                    let _ = close_err.close(CloseReason::Unexpected).await;
                    Err(err)
                })
                .and_then(|should_send| async move {
                    if should_send {
                        close_ok.close(CloseReason::Voluntary).await
                    } else {
                        Ok(())
                    }
                })
                .await;
        });
    }

    println!("{:?}: disconnected", addr);
    Ok(())
}

async fn accept_wsproxy(
    fut: upgrade::UpgradeFut,
    incoming_uri: String,
    addr: String,
    block_local: bool,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let mut ws_stream = FragmentCollector::new(fut.await?);

    println!("{:?}: connected (wsproxy): {:?}", addr, incoming_uri);

    if block_local {
        match lookup_host(&incoming_uri)
            .await
            .ok()
            .and_then(|mut x| x.next())
            .map(|x| !x.ip().is_global())
        {
            Some(true) => {
                ws_stream
                    .write_frame(Frame::close(CloseCode::Error.into(), b"blocked uri"))
                    .await?;
                return Ok(());
            }
            Some(false) => {}
            None => {
                ws_stream
                    .write_frame(Frame::close(
                        CloseCode::Error.into(),
                        b"failed to resolve uri",
                    ))
                    .await?;
                return Ok(());
            }
        }
    }

    let tcp_stream = match TcpStream::connect(incoming_uri).await {
        Ok(stream) => stream,
        Err(err) => {
            ws_stream
                .write_frame(Frame::close(CloseCode::Error.into(), b"failed to connect"))
                .await?;
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
