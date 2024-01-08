use std::io::Error;

use bytes::Bytes;
use fastwebsockets::{
    upgrade, CloseCode, FragmentCollector, Frame, OpCode, Payload, WebSocketError,
};
use futures_util::{SinkExt, StreamExt};
use hyper::{
    body::Incoming, header::HeaderValue, server::conn::http1, service::service_fn, Request,
    Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};
use tokio_util::codec::{BytesCodec, Framed};

type HttpBody = http_body_util::Empty<hyper::body::Bytes>;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let pem = include_bytes!("./pem.pem");
    let key = include_bytes!("./key.pem");
    let identity = native_tls::Identity::from_pkcs8(pem, key).expect("failed to make identity");

    let socket = TcpListener::bind("0.0.0.0:4000")
        .await
        .expect("failed to bind");
    let acceptor = TlsAcceptor::from(
        native_tls::TlsAcceptor::new(identity).expect("failed to make tls acceptor"),
    );
    let acceptor = std::sync::Arc::new(acceptor);

    println!("listening on 0.0.0.0:4000");
    while let Ok((stream, addr)) = socket.accept().await {
        let acceptor_cloned = acceptor.clone();
        tokio::spawn(async move {
            let stream = acceptor_cloned.accept(stream).await.expect("not tls");
            let io = TokioIo::new(stream);
            let service = service_fn(move |res| accept_http(res, addr.to_string()));
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
) -> Result<Response<HttpBody>, WebSocketError> {
    if upgrade::is_upgrade_request(&req) {
        let uri = req.uri().clone();
        let (mut res, fut) = upgrade::upgrade(&mut req)?;

        tokio::spawn(async move {
            if let Err(e) = accept_ws(fut, uri.path().to_string(), addr.clone()).await {
                println!("{:?}: error in ws handling: {:?}", addr, e);
            }
        });

        if let Some(protocol) = req.headers().get("Sec-Websocket-Protocol") {
            let first_protocol = protocol
                .to_str()
                .expect("failed to get protocol")
                .split(',')
                .next()
                .expect("failed to get first protocol")
                .trim();
            res.headers_mut().insert(
                "Sec-Websocket-Protocol",
                HeaderValue::from_str(first_protocol).unwrap(),
            );
        }

        Ok(res)
    } else {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(HttpBody::new())
            .unwrap())
    }
}

async fn accept_ws(
    fut: upgrade::UpgradeFut,
    incoming_uri: String,
    addr: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ws_stream = FragmentCollector::new(fut.await?);

    let mut incoming_uri_chars = incoming_uri.chars();
    incoming_uri_chars.next();

    println!("{:?}: connected", addr);

    let tcp_stream = match TcpStream::connect(incoming_uri_chars.as_str()).await {
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
                        print!("{:?}: event ws - ", addr);
                        match frame.opcode {
                            OpCode::Text | OpCode::Binary => {
                                if tcp_stream_framed.send(Bytes::from(frame.payload.to_vec())).await.is_ok() {
                                    println!("sent success");
                                } else {
                                    println!("sent FAILED");
                                }
                            }
                            OpCode::Close => {
                                if <Framed<tokio::net::TcpStream, BytesCodec> as SinkExt<Bytes>>::close(&mut tcp_stream_framed).await.is_ok() {
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
                    },
                    Err(err) => {
                        print!("{:?}: err in ws: {:?} - ", addr, err);
                        if <Framed<tokio::net::TcpStream, BytesCodec> as SinkExt<Bytes>>::close(&mut tcp_stream_framed).await.is_ok() {
                            println!("closed tcp success");
                        } else {
                            println!("closed tcp FAILED");
                        }
                        break;
                    }
                }
            },
            event = tcp_stream_framed.next() => {
                if let Some(res) = event {
                    print!("{:?}: event tcp - ", addr);
                    match res {
                        Ok(buf) => {
                            if ws_stream.write_frame(Frame::binary(Payload::Owned(buf.to_vec()))).await.is_ok() {
                                println!("sent success");
                            } else {
                                println!("sent FAILED");
                            }
                        }
                        Err(_) => {
                            if ws_stream.write_frame(Frame::close(CloseCode::Away.into(), b"tcp side is going away")).await.is_ok() {
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

    println!("\"{}\": connection closed", addr);

    Ok(())
}
