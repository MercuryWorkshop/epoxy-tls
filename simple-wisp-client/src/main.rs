use bytes::Bytes;
use fastwebsockets::{handshake, FragmentCollectorRead};
use futures::io::AsyncWriteExt;
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    Request,
};
use std::{error::Error, future::Future};
use tokio::net::TcpStream;
use tokio_native_tls::{native_tls, TlsConnector};
use wisp_mux::{ClientMux, StreamType};
use tokio_util::either::Either;

#[derive(Debug)]
struct StrError(String);

impl StrError {
    pub fn new(str: &str) -> Self {
        Self(str.to_string())
    }
}

impl std::fmt::Display for StrError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", self.0)
    }
}

impl Error for StrError {}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();
    let addr = std::env::args()
        .nth(1)
        .ok_or(StrError::new("no src addr"))?;

    let addr_port: u16 = std::env::args()
        .nth(2)
        .ok_or(StrError::new("no src port"))?
        .parse()?;

    let addr_path = std::env::args()
        .nth(3)
        .ok_or(StrError::new("no src path"))?;

    let addr_dest = std::env::args()
        .nth(4)
        .ok_or(StrError::new("no dest addr"))?;

    let addr_dest_port: u16 = std::env::args()
        .nth(5)
        .ok_or(StrError::new("no dest port"))?
        .parse()?;
    let should_tls: bool = std::env::args()
        .nth(6)
        .ok_or(StrError::new("no should tls"))?
        .parse()?;

    let socket = TcpStream::connect(format!("{}:{}", &addr, addr_port)).await?;
    let socket = if should_tls {
        let cx = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
        Either::Left(cx.connect(&addr, socket).await?)
    } else {
        Either::Right(socket)
    };
    let req = Request::builder()
        .method("GET")
        .uri(addr_path)
        .header("Host", &addr)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", "wisp-v1")
        .body(Empty::<Bytes>::new())?;

    let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

    let (rx, tx) = ws.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    let (mux, fut) = ClientMux::new(rx, tx).await?;

    tokio::task::spawn(async move { println!("err: {:?}", fut.await); });

    let mut hi: u64 = 0;
    loop {
        let mut channel = mux
            .client_new_stream(StreamType::Tcp, addr_dest.clone(), addr_dest_port)
            .await?
            .into_io()
            .into_asyncrw();
        for _ in 0..256 {
            channel.write_all(b"hiiiiiiii").await?;
            hi += 1;
            println!("said hi {}", hi);
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
