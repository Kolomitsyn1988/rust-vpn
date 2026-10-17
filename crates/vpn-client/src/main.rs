use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use vpn_core::crypto::{parse_psk, Cipher};
use vpn_core::frame::{Framed, Message};
use vpn_core::relay::relay;
use vpn_core::target::{Host, Target};

const SOCKS_TIMEOUT: Duration = Duration::from_secs(10);

/// VPN client: a local SOCKS5 proxy that sends traffic through the tunnel.
#[derive(Parser, Debug)]
#[command(name = "vpn-client", version, about = "SOCKS5 proxy backed by the VPN tunnel")]
struct Args {
    /// VPN server address, for example vpn.example.com:51820.
    #[arg(long, default_value = "127.0.0.1:51820")]
    server: String,

    /// Pre-shared key: a hex string or a path to a file containing one.
    #[arg(long)]
    psk: String,

    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks_listen: String,

    /// Maximum number of simultaneous proxied connections.
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
    let server_addr = resolve_once(&args.server).await?;

    let listener = TcpListener::bind(&args.socks_listen).await?;
    info!(socks = %args.socks_listen, server = %args.server, "SOCKS5 proxy is listening");

    let slots = Arc::new(Semaphore::new(args.max_connections));
    loop {
        let (sock, peer) = listener.accept().await?;
        let Ok(_permit) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "connection limit reached, rejecting SOCKS client");
            continue;
        };
        let cipher = Arc::clone(&cipher);
        tokio::spawn(async move {
            if let Err(err) = handle_socks(sock, server_addr, cipher).await {
                debug!(%peer, %err, "SOCKS connection finished with an error");
            }
        });
    }
}

async fn resolve_once(
    address: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(addr) = address.parse() {
        return Ok(addr);
    }
    let mut addrs = tokio::net::lookup_host(address).await?;
    addrs
        .next()
        .ok_or_else(|| format!("cannot resolve server address {address:?}").into())
}

async fn handle_socks(
    mut local: TcpStream,
    server_addr: SocketAddr,
    cipher: Arc<Cipher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target = match tokio::time::timeout(SOCKS_TIMEOUT, socks_handshake(&mut local)).await {
        Ok(Ok(target)) => target,
        Ok(Err(err)) => {
            debug!(%err, "SOCKS handshake failed");
            return Ok(());
        }
        Err(_) => {
            debug!("SOCKS handshake timed out");
            return Ok(());
        }
    };
    debug!(%target, "proxying via VPN server");

    let server = match tokio::time::timeout(SOCKS_TIMEOUT, TcpStream::connect(server_addr)).await {
        Ok(Ok(server)) => server,
        Ok(Err(err)) => {
            socks_reply(&mut local, 0x01).await.ok();
            warn!(%err, "cannot reach VPN server");
            return Ok(());
        }
        Err(_) => {
            socks_reply(&mut local, 0x01).await.ok();
            warn!("timeout while connecting to VPN server");
            return Ok(());
        }
    };

    let (server_reader, server_writer) = server.into_split();
    let mut framed = Framed::new(server_reader, server_writer, (*cipher).clone());
    framed.send(&Message::Connect(target.clone())).await?;

    match tokio::time::timeout(SOCKS_TIMEOUT, framed.recv()).await {
        Ok(Ok(Some(Message::ConnectOk))) => {}
        Ok(Ok(Some(Message::ConnectError(err)))) => {
            socks_reply(&mut local, 0x05).await.ok();
            debug!(%err, "server refused the connection");
            return Ok(());
        }
        Ok(Ok(Some(other))) => {
            socks_reply(&mut local, 0x01).await.ok();
            debug!(?other, "unexpected server message");
            return Ok(());
        }
        Ok(Ok(None)) => {
            socks_reply(&mut local, 0x01).await.ok();
            return Ok(());
        }
        Ok(Err(err)) => {
            socks_reply(&mut local, 0x01).await.ok();
            debug!(%err, "tunnel error");
            return Ok(());
        }
        Err(_) => {
            socks_reply(&mut local, 0x01).await.ok();
            debug!("server handshake timed out");
            return Ok(());
        }
    }

    socks_reply(&mut local, 0x00).await?;
    info!(%target, "connection proxied");
    let (local_reader, local_writer) = local.into_split();
    relay(framed, local_reader, local_writer).await?;
    Ok(())
}

async fn socks_handshake(
    stream: &mut TcpStream,
) -> Result<Target, Box<dyn std::error::Error + Send + Sync>> {
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(format!("bad SOCKS version {}", head[0]).into());
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err("client offers no acceptable authentication method".into());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err("bad SOCKS version in request".into());
    }
    if req[2] != 0x00 {
        return Err("bad SOCKS reserved byte".into());
    }
    match req[1] {
        0x01 => {}
        0x02 => {
            socks_reply(stream, 0x07).await?;
            return Err("SOCKS BIND is not supported".into());
        }
        0x03 => {
            socks_reply(stream, 0x07).await?;
            return Err("SOCKS UDP ASSOCIATE is not supported".into());
        }
        cmd => {
            socks_reply(stream, 0x07).await?;
            return Err(format!("unknown SOCKS command {cmd}").into());
        }
    }
    let host = match req[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            Host::Domain(String::from_utf8_lossy(&name).into_owned())
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        atyp => {
            socks_reply(stream, 0x08).await?;
            return Err(format!("unsupported address type {atyp}").into());
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

async fn socks_reply(stream: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    // VER REP RSV ATYP BND.ADDR(0.0.0.0) BND.PORT(0)
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}
