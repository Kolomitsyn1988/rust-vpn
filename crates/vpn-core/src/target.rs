//! Destination addresses used in `CONNECT` messages.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

/// A destination host: either a literal IP address or a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl From<IpAddr> for Host {
    fn from(ip: IpAddr) -> Self {
        Host::Ip(ip)
    }
}

/// A destination host plus port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<Host>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Resolves the target into socket addresses (blocking DNS).
    pub fn resolve(&self) -> std::io::Result<Vec<SocketAddr>> {
        match &self.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, self.port)]),
            Host::Domain(domain) => Ok((domain.as_str(), self.port).to_socket_addrs()?.collect()),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{}]:{}", v6, self.port),
            Host::Ip(ip) => write!(f, "{}:{}", ip, self.port),
            Host::Domain(domain) => write!(f, "{}:{}", domain, self.port),
        }
    }
}

impl FromStr for Target {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| format!("expected host:port, got {value:?}"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("invalid port in {value:?}"))?;
        let host = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(host.trim_matches(['[', ']']).to_string()),
        };
        Ok(Target { host, port })
    }
}
