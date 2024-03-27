use atomic_counter::{AtomicCounter, RelaxedCounter};
use bytes::Bytes;
use fastwebsockets::{handshake, FragmentCollectorRead};
use futures::future::select_all;
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    Request,
};
use simple_moving_average::{SingleSumSMA, SMA};
use std::{
    error::Error,
    future::Future,
    io::{stdout, IsTerminal, Write},
    sync::Arc,
    time::Duration,
    usize,
};
use tokio::{net::TcpStream, time::interval};
use tokio_native_tls::{native_tls, TlsConnector};
use tokio_util::either::Either;
use wisp_mux::{ClientMux, StreamType, WispError};

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
    let thread_cnt: usize = std::env::args().nth(7).unwrap_or("10".into()).parse()?;

    println!(
        "connecting to {}://{}:{}{} and sending &[0; 1024] to {}:{} with threads {}",
        if should_tls { "wss" } else { "ws" },
        addr,
        addr_port,
        addr_path,
        addr_dest,
        addr_dest_port,
        thread_cnt
    );

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
    let mut threads = Vec::with_capacity(thread_cnt + 1);

    threads.push(tokio::spawn(fut));

    let payload = Bytes::from_static(&[0; 1024]);

    let cnt = Arc::new(RelaxedCounter::new(0));

    for _ in 0..thread_cnt {
        let mut channel = mux
            .client_new_stream(StreamType::Tcp, addr_dest.clone(), addr_dest_port)
            .await?;
        let cnt = cnt.clone();
        let payload = payload.clone();
        threads.push(tokio::spawn(async move {
            loop {
                channel.write(payload.clone()).await?;
                channel.read().await;
                cnt.inc();
            }
            #[allow(unreachable_code)]
            Ok::<(), WispError>(())
        }));
    }

    threads.push(tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(100));
        let mut avg: SingleSumSMA<usize, usize, 100> = SingleSumSMA::new();
        let mut last_time = 0;
        let is_term = stdout().is_terminal();
        loop {
            interval.tick().await;
            let now = cnt.get();
            let stat = format!(
                "sent &[0; 1024] cnt: {:?}, +{:?}, moving average (100): {:?}",
                now,
                now - last_time,
                avg.get_average()
            );
            if is_term {
                print!("\x1b[2K{}\r", stat);
            } else {
                println!("{}", stat);
            }
            stdout().flush().unwrap();
            avg.add_sample(now - last_time);
            last_time = now;
        }
    }));

    let out = select_all(threads.into_iter()).await;

    println!("\n\nout: {:?}", out.0);

    Ok(())
}
