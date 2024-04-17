#![feature(let_chains, ip)]
use std::{collections::HashMap, io::Error, path::PathBuf, sync::Arc};

use bytes::Bytes;
use clap::Parser;
use fastwebsockets::{
    upgrade::{self, UpgradeFut},
    CloseCode, FragmentCollector, FragmentCollectorRead, Frame, OpCode, Payload, WebSocketError,
};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::copy_bidirectional,
    net::{lookup_host, TcpListener, TcpStream, UdpSocket},
};
use tokio_util::codec::{BytesCodec, Framed};
#[cfg(unix)]
use tokio_util::either::Either;

use wisp_mux::{
    extensions::{
        password::{PasswordProtocolExtension, PasswordProtocolExtensionBuilder},
        udp::UdpProtocolExtensionBuilder,
        ProtocolExtensionBuilder,
    },
    CloseReason, ConnectPacket, MuxStream, ServerMux, StreamType, WispError,
};

type HttpBody = http_body_util::Full<hyper::body::Bytes>;

/// Server implementation of the Wisp protocol in Rust, made for epoxy
#[derive(Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
    /// URL prefix the server should serve on
    #[arg(long)]
    prefix: Option<String>,
    /// Port the server should bind to
    #[arg(long, short, default_value = "4000")]
    port: String,
    /// Host the server should bind to
    #[arg(long = "host", short, value_name = "HOST", default_value = "0.0.0.0")]
    bind_host: String,
    /// Whether the server should listen on a Unix socket located at the value of the host argument
    #[arg(long, short)]
    unix_socket: bool,
    /// Whether the server should block IP addresses that are not globally reachable
    ///
    /// See https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_global for which IP
    /// addresses are blocked
    #[arg(long, short = 'B')]
    block_local: bool,
    /// Whether the server should block UDP
    ///
    /// This does nothing for wsproxy as that is always TCP
    #[arg(long)]
    block_udp: bool,
    /// Whether the server should block ports other than 80 or 443
    #[arg(long)]
    block_non_http: bool,
    /// Path to a file containing `user:password` separated by newlines. This is plaintext!!!
    ///
    /// `user` cannot contain `:`. Whitespace will be trimmed.
    #[arg(long)]
    auth: Option<PathBuf>,
}

#[derive(Clone)]
struct MuxOptions {
    pub block_local: bool,
    pub block_udp: bool,
    pub block_non_http: bool,
    pub enforce_auth: bool,
    pub auth: Arc<Vec<Box<(dyn ProtocolExtensionBuilder + Send + Sync)>>>,
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

    let prefix = if let Some(prefix) = opt.prefix {
        match (prefix.starts_with('/'), prefix.ends_with('/')) {
            (true, true) => prefix,
            (true, false) => prefix + "/",
            (false, true) => "/".to_string() + &prefix,
            (false, false) => "/".to_string() + &prefix + "/",
        }
    } else {
        "/".to_string()
    };

    let mut auth = HashMap::new();
    let enforce_auth = opt.auth.is_some();
    if let Some(file) = opt.auth {
        let file = std::fs::read_to_string(file)?;
        for entry in file.split('\n').filter_map(|x| {
            if x.contains(':') {
                Some(x.trim())
            } else {
                None
            }
        }) {
            let split: Vec<_> = entry.split(':').collect();
            let username = split[0];
            let password = split[1..].join(":");
            println!(
                "adding username {:?} password {:?} to allowed auth",
                username, password
            );
            auth.insert(username.to_string(), password.to_string());
        }
    }
    let pw_ext = PasswordProtocolExtensionBuilder::new_server(auth);

    let mux_options = MuxOptions {
        block_local: opt.block_local,
        block_non_http: opt.block_non_http,
        block_udp: opt.block_udp,
        auth: Arc::new(vec![
            Box::new(UdpProtocolExtensionBuilder()),
            Box::new(pw_ext),
        ]),
        enforce_auth,
    };

    println!("listening on `{}` with prefix `{}`", addr, prefix);
    while let Ok((stream, addr)) = socket.accept().await {
        let prefix = prefix.clone();
        let mux_options = mux_options.clone();
        tokio::spawn(async move {
            let service = service_fn(move |res| {
                accept_http(res, addr.clone(), prefix.clone(), mux_options.clone())
            });
            let conn = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
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
    mux_options: MuxOptions,
) -> Result<Response<HttpBody>, WebSocketError> {
    let uri = req.uri().path().to_string();
    if upgrade::is_upgrade_request(&req)
        && let Some(uri) = uri.strip_prefix(&prefix)
    {
        let (res, fut) = upgrade::upgrade(&mut req)?;

        if uri.is_empty() {
            tokio::spawn(async move { accept_ws(fut, addr.clone(), mux_options).await });
        } else if let Some(uri) = uri.strip_prefix('/').map(|x| x.to_string()) {
            tokio::spawn(async move {
                accept_wsproxy(
                    fut,
                    uri,
                    addr.clone(),
                    mux_options.block_local,
                    mux_options.block_non_http,
                )
                .await
            });
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

async fn handle_mux(packet: ConnectPacket, stream: MuxStream) -> Result<bool, WispError> {
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
            copy_bidirectional(&mut mux_stream, &mut tcp_stream)
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
        StreamType::Unknown(_) => {
            stream.close(CloseReason::ServerStreamInvalidInfo).await?;
            return Ok(false);
        }
    }
    Ok(true)
}

async fn accept_ws(
    ws: UpgradeFut,
    addr: String,
    mux_options: MuxOptions,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (rx, tx) = ws.await?.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    println!("{:?}: connected", addr);
    // to prevent memory ""leaks"" because users are sending in packets way too fast the buffer
    // size is set to 128
    let (mux, fut) = if mux_options.enforce_auth {
        let (mux, fut) = ServerMux::new(rx, tx, 128, Some(mux_options.auth.as_slice())).await?;
        if !mux
            .supported_extension_ids
            .iter()
            .any(|x| *x == PasswordProtocolExtension::ID)
        {
            println!(
                "{:?}: client did not support auth or password was invalid",
                addr
            );
            mux.close_extension_incompat().await?;
            return Ok(());
        }
        (mux, fut)
    } else {
        ServerMux::new(
            rx,
            tx,
            128,
            Some(&[Box::new(UdpProtocolExtensionBuilder())]),
        )
        .await?
    };

    println!(
        "{:?}: downgraded: {} extensions supported: {:?}",
        addr, mux.downgraded, mux.supported_extension_ids
    );

    tokio::spawn(async move {
        if let Err(e) = fut.await {
            println!("err in mux: {:?}", e);
        }
    });

    while let Some((packet, stream)) = mux.server_new_stream().await {
        tokio::spawn(async move {
            if (mux_options.block_non_http
                && !(packet.destination_port == 80 || packet.destination_port == 443))
                || (mux_options.block_udp && packet.stream_type == StreamType::Udp)
            {
                let _ = stream.close(CloseReason::ServerStreamBlockedAddress).await;
                return;
            }
            if mux_options.block_local {
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
                        let _ = close_ok.close(CloseReason::Voluntary).await;
                    }
                    Ok(())
                })
                .await;
        });
    }

    println!("{:?}: disconnected", addr);
    Ok(())
}

async fn accept_wsproxy(
    ws: UpgradeFut,
    incoming_uri: String,
    addr: String,
    block_local: bool,
    block_non_http: bool,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let mut ws_stream = FragmentCollector::new(ws.await?);

    println!("{:?}: connected (wsproxy): {:?}", addr, incoming_uri);

    let Some(host) = lookup_host(&incoming_uri)
        .await
        .ok()
        .and_then(|mut x| x.next())
    else {
        ws_stream
            .write_frame(Frame::close(
                CloseCode::Error.into(),
                b"failed to resolve uri",
            ))
            .await?;
        return Ok(());
    };

    if block_local && !host.ip().is_global() {
        ws_stream
            .write_frame(Frame::close(CloseCode::Error.into(), b"blocked uri"))
            .await?;
        return Ok(());
    }

    if block_non_http && !(host.port() == 80 || host.port() == 443) {
        ws_stream
            .write_frame(Frame::close(CloseCode::Error.into(), b"blocked uri"))
            .await?;
        return Ok(());
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
