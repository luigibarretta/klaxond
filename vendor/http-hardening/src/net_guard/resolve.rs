//! Resolve-once-and-pin: DNS is queried a single time, every answer is
//! checked, and the checked addresses are handed back to the caller.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use url::{Host, Url};

use super::error::NetGuardError;
use super::NetGuard;

/// Hard upper bound on addresses accepted from one DNS answer.
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

/// Pluggable DNS lookup, so tests and async callers can supply answers.
pub trait DnsLookup {
    /// Returns the addresses of `host` (a DNS name, never a literal).
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// Blocking system resolver (`getaddrinfo` through std). Call it from a
/// blocking context (e.g. `tokio::task::spawn_blocking`) in async code, or
/// resolve asynchronously and pass the answer to
/// [`NetGuard::check_addresses`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDns;

impl DnsLookup for SystemDns {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port)
            .to_socket_addrs()?
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect())
    }
}

impl<F> DnsLookup for F
where
    F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
{
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self(host, port)
    }
}

/// A validated destination: connect only to [`ResolvedTarget::addrs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTarget {
    url: Url,
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

impl ResolvedTarget {
    /// The checked URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Host as it appears in the URL (lowercase; IPv6 without brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Destination port (explicit or scheme default).
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Checked, canonical socket addresses; never empty.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Splits the target into its URL and addresses.
    pub fn into_parts(self) -> (Url, Vec<SocketAddr>) {
        (self.url, self.addrs)
    }
}

impl NetGuard {
    /// Checks `url`, resolves it once with the system resolver and checks
    /// every resolved address. Blocking.
    pub fn resolve(&self, url: &Url) -> Result<ResolvedTarget, NetGuardError> {
        self.resolve_with(url, &SystemDns)
    }

    /// Like [`NetGuard::resolve`] with a caller-supplied resolver.
    pub fn resolve_with<D>(&self, url: &Url, dns: &D) -> Result<ResolvedTarget, NetGuardError>
    where
        D: DnsLookup + ?Sized,
    {
        self.check_url(url)?;
        let port = url
            .port_or_known_default()
            .ok_or(NetGuardError::MissingPort)?;
        let (host, answer) = match url.host() {
            None => return Err(NetGuardError::MissingHost),
            Some(Host::Ipv4(ip)) => (ip.to_string(), vec![SocketAddr::new(IpAddr::V4(ip), port)]),
            Some(Host::Ipv6(ip)) => (ip.to_string(), vec![SocketAddr::new(IpAddr::V6(ip), port)]),
            Some(Host::Domain(name)) => {
                let answer = dns
                    .lookup(name, port)
                    .map_err(|source| NetGuardError::Dns {
                        host: name.to_owned(),
                        source,
                    })?;
                (name.to_owned(), answer)
            }
        };
        let addrs = self.check_addresses(&host, port, answer)?;
        Ok(ResolvedTarget {
            url: url.clone(),
            host,
            port,
            addrs,
        })
    }

    /// Checks a DNS answer obtained elsewhere (e.g. `tokio::net::lookup_host`).
    /// Every address must pass, otherwise the whole answer is refused: a mixed
    /// public/private answer is a classic rebinding setup. Returned addresses
    /// are canonical and carry `port`.
    pub fn check_addresses<I>(
        &self,
        host: &str,
        port: u16,
        answer: I,
    ) -> Result<Vec<SocketAddr>, NetGuardError>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let limit = self.max_addresses;
        let mut checked = Vec::new();
        for addr in answer.into_iter().take(limit.saturating_add(1)) {
            if checked.len() == limit {
                return Err(NetGuardError::TooManyAddresses {
                    host: host.to_owned(),
                    limit,
                });
            }
            let ip = self.check_ip(addr.ip())?;
            let pinned = SocketAddr::new(ip, port);
            if !checked.contains(&pinned) {
                checked.push(pinned);
            }
        }
        if checked.is_empty() {
            return Err(NetGuardError::NoAddresses(host.to_owned()));
        }
        Ok(checked)
    }
}
