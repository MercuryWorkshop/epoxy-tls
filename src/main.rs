use std::{convert::Infallible, io::Error};

use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use hyper::{
    body::Incoming,
    header::{
        HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION,
        UPGRADE,
    },
    server::conn::http1,
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response, StatusCode, Version
};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    tungstenite::{protocol::Role, handshake::derive_accept_key, Message},
    WebSocketStream,
};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

struct NetworkCodec;

impl Encoder<Vec<u8>> for NetworkCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_slice(item.as_slice());
        Ok(())
    }
}

impl Decoder for NetworkCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Some(src.to_vec()))
    }
}

type HttpBody = http_body_util::Full<hyper::body::Bytes>;

#[tokio::main(flavor = "multi_thread", worker_threads = 32)]
async fn main() -> Result<(), Error> {
    let socket = TcpListener::bind("0.0.0.0:4000")
        .await
        .expect("failed to bind");

    println!("listening on 0.0.0.0:4000");
    while let Ok((stream, addr)) = socket.accept().await {
        println!("socket connected: {:?}", addr);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(accept_http);
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

async fn accept_http(mut req: Request<Incoming>) -> Result<Response<HttpBody>, Infallible> {
    let incoming_uri = req.uri().clone();
    let req_ver = req.version();
    let req_headers = req.headers().clone();
    let req_key = req_headers.get(SEC_WEBSOCKET_KEY);
    let derived_key = req_key.map(|k| derive_accept_key(k.as_bytes()));

    if req.method() != Method::GET
        || req.version() < Version::HTTP_11
        || !req_headers
            .get(CONNECTION)
            .and_then(|h| h.to_str().ok())
            .map(|h| {
                h.split(|c| c == ' ' || c == ',')
                    .any(|p| p.eq_ignore_ascii_case("Upgrade"))
            })
            .unwrap_or(false)
        || !req_headers
            .get(UPGRADE)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        || !req_headers.get(SEC_WEBSOCKET_VERSION).map(|h| h == "13").unwrap_or(false)
        || req_key.is_none()
    {
        return Ok(Response::new(HttpBody::from("Hello World!")));
    }

    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                println!("upgraded connection");
                let upgraded_io = TokioIo::new(upgraded);
                accept_ws(
                    WebSocketStream::from_raw_socket(upgraded_io, Role::Server, None).await,
                    incoming_uri.path().to_string(),
                ).await;
            }
            Err(e) => {
                println!("upgrade error! {:?}", e);
            }
        }
    });

    println!("sending upgrade response");

    let mut res = Response::new(HttpBody::default());
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *res.version_mut() = req_ver;
    res.headers_mut()
        .append(CONNECTION, HeaderValue::from_static("Upgrade"));
    res.headers_mut()
        .append(UPGRADE, HeaderValue::from_static("websocket"));
    res.headers_mut().append(SEC_WEBSOCKET_ACCEPT, derived_key.unwrap().parse().unwrap());

    Ok(res)
}

async fn accept_ws(mut ws_stream: WebSocketStream<TokioIo<Upgraded>>, incoming_uri: String) {
    println!("new ws connection: {}", incoming_uri);

    let mut incoming_uri_chars = incoming_uri.chars();
    incoming_uri_chars.next();

    let tcp_stream = TcpStream::connect(incoming_uri_chars.as_str())
        .await
        .expect("failed to connect to incoming uri");
    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);
    let mut tcp_write = FramedWrite::new(tcp_write, NetworkCodec);
    let mut tcp_read = FramedRead::new(tcp_read, NetworkCodec);

    loop {
        tokio::select! {
            event = ws_stream.next() => {
                if let Some(Ok(payload)) = event {
                    print!("event ws {:?} - ", payload);
                    match payload {
                        Message::Text(txt) => {
                            if tcp_write.send(txt.into_bytes()).await.is_ok() {
                                println!("sent success");
                            } else {
                                println!("sent FAILED");
                            }
                        }
                        Message::Binary(bin) => {
                            if tcp_write.send(bin).await.is_ok() {
                                println!("sent success");
                            } else {
                                println!("sent FAILED");
                            }
                        }
                        Message::Close(_) => {
                            if tcp_write.close().await.is_ok() {
                                println!("closed success");
                            } else {
                                println!("closed FAILED");
                            }
                            break;
                        }
                        _ => {
                            println!("ignored");
                        }
                    }
                }
            },
            event = tcp_read.next() => {
                if let Some(res) = event {
                    print!("event tcp - ");
                    match res {
                        Ok(buf) => {
                            if ws_stream.send(Message::Binary(buf)).await.is_ok() {
                                println!("sent success");
                            } else {
                                println!("sent FAILED");
                            }
                        }
                        Err(_) => {
                            if ws_stream.close(None).await.is_ok() {
                                println!("closed success");
                            } else {
                                println!("closed FAILED");
                            }
                        }
                    }
                }
            }
        }
    }
    println!("connection closed");
}
