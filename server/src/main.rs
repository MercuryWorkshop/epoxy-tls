use std::{convert::Infallible, env, net::SocketAddr, sync::Arc};

use hyper::{
    body::Incoming,
    header::{
        HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    server::conn::http1,
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response, StatusCode, Version,
};
use hyper_util::rt::TokioIo;
use penguin_mux::{Multiplexor, MuxStream};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinError, JoinSet},
};
use tokio_native_tls::{native_tls, TlsAcceptor};
use tokio_tungstenite::{
    tungstenite::{handshake::derive_accept_key, protocol::Role},
    WebSocketStream,
};

type Body = http_body_util::Empty<hyper::body::Bytes>;

type MultiplexorStream = MuxStream<WebSocketStream<TokioIo<Upgraded>>>;

async fn forward(mut stream: MultiplexorStream) -> Result<(), JoinError> {
    println!("forwarding");
    let host = std::str::from_utf8(&stream.dest_host).unwrap();
    let mut tcp_stream = TcpStream::connect((host, stream.dest_port)).await.unwrap();
    println!("connected to {:?}", tcp_stream.peer_addr().unwrap());
    tokio::io::copy_bidirectional(&mut stream, &mut tcp_stream)
        .await
        .unwrap();
    println!("finished");
    Ok(())
}

async fn handle_connection(ws_stream: WebSocketStream<TokioIo<Upgraded>>, addr: SocketAddr) {
    println!("WebSocket connection established: {}", addr);
    let mux = Multiplexor::new(ws_stream, penguin_mux::Role::Server, None, None);
    let mut jobs = JoinSet::new();
    println!("muxing");
    loop {
        tokio::select! {
            Some(result) = jobs.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) | Err(err) => eprintln!("failed to forward: {:?}", err),
                }
            }
            Ok(result) = mux.server_new_stream_channel() => {
                jobs.spawn(forward(result));
            }
            else => {
                break;
            }
        }
    }
    println!("{} disconnected", &addr);
}

async fn handle_request(
    mut req: Request<Incoming>,
    addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let headers = req.headers();
    let derived = headers
        .get(SEC_WEBSOCKET_KEY)
        .map(|k| derive_accept_key(k.as_bytes()));

    let mut negotiated_protocol: Option<String> = None;
    if let Some(protocols) = headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|h| h.to_str().ok())
    {
        negotiated_protocol = protocols.split(',').next().map(|h| h.trim().to_string());
    }

    if req.method() != Method::GET
        || req.version() < Version::HTTP_11
        || !headers
            .get(CONNECTION)
            .and_then(|h| h.to_str().ok())
            .map(|h| {
                h.split(|c| c == ' ' || c == ',')
                    .any(|p| p.eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false)
        || !headers
            .get(UPGRADE)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        || !headers
            .get(SEC_WEBSOCKET_VERSION)
            .map(|h| h == "13")
            .unwrap_or(false)
        || derived.is_none()
    {
        return Ok(Response::new(Body::default()));
    }

    let ver = req.version();
    tokio::task::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                let upgraded = TokioIo::new(upgraded);
                handle_connection(
                    WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await,
                    addr,
                )
                .await;
            }
            Err(e) => eprintln!("upgrade error: {}", e),
        }
    });

    let mut res = Response::new(Body::default());
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *res.version_mut() = ver;
    res.headers_mut()
        .append(CONNECTION, HeaderValue::from_static("Upgrade"));
    res.headers_mut()
        .append(UPGRADE, HeaderValue::from_static("websocket"));
    res.headers_mut()
        .append(SEC_WEBSOCKET_ACCEPT, derived.unwrap().parse().unwrap());
    if let Some(protocol) = negotiated_protocol {
        res.headers_mut()
            .append(SEC_WEBSOCKET_PROTOCOL, protocol.parse().unwrap());
    }

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:4000".to_string())
        .parse::<SocketAddr>()?;
    let pem = include_bytes!("./pem.pem");
    let key = include_bytes!("./key.pem");

    let identity = native_tls::Identity::from_pkcs8(pem, key).expect("invalid pem/key");

    let acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
    let acceptor = Arc::new(acceptor);

    let listener = TcpListener::bind(addr).await?;

    println!("listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await.expect("not tls");
            let io = TokioIo::new(stream);

            let service = service_fn(move |req| handle_request(req, remote_addr));

            let conn = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades();

            if let Err(err) = conn.await {
                eprintln!("failed to serve connection: {:?}", err);
            }
        });
    }
}
