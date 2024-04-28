use atomic_counter::{AtomicCounter, RelaxedCounter};
use bytes::Bytes;
use clap::Parser;
use fastwebsockets::{handshake, FragmentCollectorRead};
use futures::future::select_all;
use http_body_util::Empty;
use humantime::format_duration;
use hyper::{
    header::{CONNECTION, UPGRADE},
    Request, Uri,
};
use simple_moving_average::{SingleSumSMA, SMA};
use std::{
    error::Error,
    future::Future,
    io::{stdout, IsTerminal, Write},
    net::SocketAddr,
    process::exit,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    select,
    signal::unix::{signal, SignalKind},
    time::{interval, sleep},
};
use tokio_native_tls::{native_tls, TlsConnector};
use tokio_util::either::Either;
use wisp_mux::{
    extensions::{
        password::{PasswordProtocolExtension, PasswordProtocolExtensionBuilder},
        udp::{UdpProtocolExtension, UdpProtocolExtensionBuilder},
        ProtocolExtensionBuilder,
    },
    ClientMux, StreamType, WispError,
};

#[derive(Debug)]
enum WispClientError {
    InvalidUriScheme,
    UriHasNoHost,
}

impl std::fmt::Display for WispClientError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        use WispClientError as E;
        match self {
            E::InvalidUriScheme => write!(fmt, "Invalid URI scheme"),
            E::UriHasNoHost => write!(fmt, "URI has no host"),
        }
    }
}

impl Error for WispClientError {}

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

#[derive(Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
    /// Wisp server URL
    #[arg(short, long)]
    wisp: Uri,
    /// TCP server address
    #[arg(short, long)]
    tcp: SocketAddr,
    /// Number of streams
    #[arg(short, long, default_value_t = 10)]
    streams: usize,
    /// Size of packets sent, in KB
    #[arg(short, long, default_value_t = 1)]
    packet_size: usize,
    /// Duration to run the test for
    #[arg(short, long)]
    duration: Option<humantime::Duration>,
    /// Ask for UDP
    #[arg(short, long)]
    udp: bool,
    /// Enable auth: format is `username:password`
    ///
    /// Usernames and passwords are sent in plaintext!!
    #[arg(long)]
    auth: Option<String>,
    /// Make a Wisp V1 connection
    #[arg(long)]
    wisp_v1: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();
    let opts = Cli::parse();

    let tls = match opts
        .wisp
        .scheme_str()
        .ok_or(WispClientError::InvalidUriScheme)?
    {
        "wss" => Ok(true),
        "ws" => Ok(false),
        _ => Err(WispClientError::InvalidUriScheme),
    }?;
    let addr = opts.wisp.host().ok_or(WispClientError::UriHasNoHost)?;
    let addr_port = opts.wisp.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let addr_path = opts.wisp.path();
    let addr_dest = opts.tcp.ip().to_string();
    let addr_dest_port = opts.tcp.port();

    let auth = opts.auth.map(|auth| {
        let split: Vec<_> = auth.split(':').collect();
        let username = split[0].to_string();
        let password = split[1..].join(":");
        PasswordProtocolExtensionBuilder::new_client(username, password)
    });

    println!(
        "connecting to {} and sending &[0; 1024 * {}] to {} with threads {}",
        opts.wisp, opts.packet_size, opts.tcp, opts.streams,
    );

    let socket = TcpStream::connect(format!("{}:{}", &addr, addr_port)).await?;
    let socket = if tls {
        let cx = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
        Either::Left(cx.connect(addr, socket).await?)
    } else {
        Either::Right(socket)
    };
    let req = Request::builder()
        .method("GET")
        .uri(addr_path)
        .header("Host", addr)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .body(Empty::<Bytes>::new())?;

    let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

    let (rx, tx) = ws.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    let mut extensions: Vec<Box<(dyn ProtocolExtensionBuilder + Send + Sync)>> = Vec::new();
    let mut extension_ids: Vec<u8> = Vec::new();
    if opts.udp {
        extensions.push(Box::new(UdpProtocolExtensionBuilder()));
        extension_ids.push(UdpProtocolExtension::ID);
    }
    if let Some(auth) = auth {
        extensions.push(Box::new(auth));
        extension_ids.push(PasswordProtocolExtension::ID);
    }

    let (mux, fut) = if opts.wisp_v1 {
        ClientMux::create(rx, tx, None)
            .await?
            .with_no_required_extensions()
    } else {
        ClientMux::create(rx, tx, Some(extensions.as_slice()))
            .await?
            .with_required_extensions(extension_ids.as_slice()).await?
    };

    println!(
        "connected and created ClientMux, was downgraded {}, extensions supported {:?}",
        mux.downgraded, mux.supported_extension_ids
    );

    let mut threads = Vec::with_capacity(opts.streams + 4);
    let mut reads = Vec::with_capacity(opts.streams);

    threads.push(tokio::spawn(fut));

    let payload = Bytes::from(vec![0; 1024 * opts.packet_size]);

    let cnt = Arc::new(RelaxedCounter::new(0));

    let start_time = Instant::now();
    for _ in 0..opts.streams {
        let (cr, cw) = mux
            .client_new_stream(StreamType::Tcp, addr_dest.clone(), addr_dest_port)
            .await?
            .into_split();
        let cnt = cnt.clone();
        let payload = payload.clone();
        threads.push(tokio::spawn(async move {
            loop {
                cw.write(payload.clone()).await?;
                cnt.inc();
            }
            #[allow(unreachable_code)]
            Ok::<(), WispError>(())
        }));
        reads.push(cr);
    }

    threads.push(tokio::spawn(async move {
        loop {
            select_all(reads.iter().map(|x| Box::pin(x.read()))).await;
        }
    }));

    let cnt_avg = cnt.clone();
    threads.push(tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(100));
        let mut avg: SingleSumSMA<usize, usize, 100> = SingleSumSMA::new();
        let mut last_time = 0;
        let is_term = stdout().is_terminal();
        loop {
            interval.tick().await;
            let now = cnt_avg.get();
            let stat = format!(
                "sent &[0; 1024 * {}] cnt: {:?} ({} KiB), +{:?} / 100ms ({} KiB / 1s), moving average (10 s): {:?} / 100ms ({} KiB / 1s)",
                opts.packet_size,
                now,
                now * opts.packet_size,
                now - last_time,
                (now - last_time) * opts.packet_size * 10,
                avg.get_average(),
                avg.get_average() * opts.packet_size * 10,
            );
            if is_term {
                println!("\x1b[1A\x1b[2K{}\r", stat);
            } else {
                println!("{}", stat);
            }
            stdout().flush().unwrap();
            avg.add_sample(now - last_time);
            last_time = now;
        }
    }));

    threads.push(tokio::spawn(async move {
        let mut interrupt =
            signal(SignalKind::interrupt()).map_err(|x| WispError::Other(Box::new(x)))?;
        let mut terminate =
            signal(SignalKind::terminate()).map_err(|x| WispError::Other(Box::new(x)))?;
        select! {
            _ = interrupt.recv() => (),
            _ = terminate.recv() => (),
        }
        Ok(())
    }));

    if let Some(duration) = opts.duration {
        threads.push(tokio::spawn(async move {
            sleep(duration.into()).await;
            Ok(())
        }));
    }

    let out = select_all(threads.into_iter()).await;

    let duration_since = Instant::now().duration_since(start_time);

    if let Err(err) = out.0? {
        println!("\n\nerr: {:?}", err);
        exit(1);
    }

    out.2.into_iter().for_each(|x| x.abort());

    mux.close().await?;

    if duration_since.as_secs() != 0 {
        println!(
            "\nresults: {} packets of &[0; 1024 * {}] ({} KiB) sent in {} ({} KiB/s)",
            cnt.get(),
            opts.packet_size,
            cnt.get() * opts.packet_size,
            format_duration(duration_since),
            (cnt.get() * opts.packet_size) as u64 / duration_since.as_secs(),
        );
    }

    Ok(())
}
