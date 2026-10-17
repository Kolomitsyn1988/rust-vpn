use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use vpn_core::crypto::{parse_psk, Cipher};
use vpn_core::frame::{Framed, Message};
use vpn_core::relay::relay;
use vpn_core::target::{Host, Target};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// VPN tunnel server: accepts encrypted tunnels and dials real targets.
#[derive(Parser, Debug)]
#[command(name = "vpn-server", version, about = "VPN tunnel server (TCP)")]
struct Args {
    /// Address to listen on, for example 0.0.0.0:51820.
    #[arg(long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Pre-shared key: a hex string or a path to a file containing one.
    #[arg(long)]
    psk: String,

    /// Maximum number of simultaneous tunnel connections.
    #[arg(long, default_value_t = 128)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let psk = parse_psk(&args.psk)?;
    let cipher = Arc::new(Cipher::new(&psk)?);

    let listener = TcpListener::bind(&args.listen).await?;
    info!(listen = %args.listen, "vpn-server is listening");

    let slots = Arc::new(Semaphore::new(args.max_connections));
    loop {
        let (sock, peer) = listener.accept().await?;
        let Ok(_permit) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "connection limit reached, rejecting new tunnel");
            continue;
        };
        let cipher = Arc::clone(&cipher);
        tokio::spawn(async move {
            if let Err(err) = handle_tunnel(sock, cipher).await {
                debug!(%peer, %err, "tunnel finished with an error");
            }
        });
    }
}

async fn handle_tunnel(
    sock: TcpStream,
    cipher: Arc<Cipher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, writer) = sock.into_split();
    let mut framed = Framed::new(reader, writer, (*cipher).clone());

    let target = match tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.recv()).await {
        Ok(Ok(Some(Message::Connect(target)))) => target,
        Ok(Ok(Some(other))) => {
            framed
                .send(&Message::ConnectError(format!(
                    "expected CONNECT, got {other:?}"
                )))
                .await?;
            return Ok(());
        }
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => {
            let _ = framed
                .send(&Message::ConnectError("handshake timed out".to_string()))
                .await;
            return Ok(());
        }
    };
    debug!(%target, "dialing target");

    let upstream = match dial(&target).await {
        Ok(stream) => stream,
        Err(err) => {
            warn!(%target, %err, "cannot reach target");
            framed.send(&Message::ConnectError(err.to_string())).await?;
            return Ok(());
        }
    };

    framed.send(&Message::ConnectOk).await?;
    info!(%target, "tunnel established");
    let (upstream_reader, upstream_writer) = upstream.into_split();
    relay(framed, upstream_reader, upstream_writer).await?;
    Ok(())
}

async fn dial(target: &Target) -> std::io::Result<TcpStream> {
    use std::net::SocketAddr;

    let addrs: Vec<SocketAddr> = match &target.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
        Host::Domain(domain) => tokio::net::lookup_host((domain.as_str(), target.port))
            .await?
            .collect(),
    };

    let mut last_error = None;
    for addr in addrs {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(err),
            Err(_) => {
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dial timed out",
                ))
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses to dial")
    }))
}
