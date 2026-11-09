//! Resolution of the real client address behind trusted reverse proxies.
//!
//! The module only implements the algorithm and validated configuration
//! types. Reading the TCP peer address and the header values from a request,
//! and deciding what the resolved address is used for (rate-limit keys,
//! audit context), stay in the application.
//!
//! Algorithm:
//!
//! 1. An untrusted TCP peer is the client; forwarding headers are ignored.
//! 2. Otherwise only the single header named by
//!    [`TrustedProxies::header`] is read, from the right. Trusted hops are
//!    skipped and the first untrusted address is the client.
//! 3. A malformed hop reached before that address (or a non-UTF-8 value, or
//!    a client not found within the right-most [`MAX_FORWARDED_HOPS`]
//!    entries, i.e. 32 or more trusted hops before it) makes the whole header
//!    unusable and the peer is returned. The left-most, client-controlled
//!    entry is never chosen unless every hop up to it is a trusted proxy.
//!
//! Entries to the left of the first untrusted address are written by the
//! client and are not even parsed, so injected garbage cannot force every
//! request onto the proxy address (which would merge all clients into one
//! rate-limit bucket).

mod headers;
mod network;

use std::fmt;
use std::net::IpAddr;

pub use headers::ForwardingHeaders;
pub use network::normalize;
use network::IpNetwork;

/// Only the right-most `MAX_FORWARDED_HOPS` header entries are examined.
/// The client must be among them, so at most `MAX_FORWARDED_HOPS - 1` (31)
/// trusted hops may precede it; exactly `MAX_FORWARDED_HOPS` trusted hops
/// followed by the client already fall back to the peer. A header made only
/// of trusted hops resolves to its left-most entry if it has at most
/// `MAX_FORWARDED_HOPS` entries, and to the peer otherwise.
pub const MAX_FORWARDED_HOPS: usize = 32;

/// The single forwarding header the trusted proxies are known to overwrite or
/// append to. Reading any other header would trust client-supplied values
/// that the proxy passes through untouched.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ForwardingHeader {
    /// `X-Forwarded-For` (Traefik, nginx, Authentik outposts).
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`, using the `for=` parameter.
    Forwarded,
    /// `X-Real-IP`; exactly one address is accepted.
    XRealIp,
}

/// Where the resolved address came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIpSource {
    Peer,
    Header,
}

/// A validated set of trusted proxy networks plus the header they maintain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedProxies {
    networks: Vec<IpNetwork>,
    header: ForwardingHeader,
}

impl TrustedProxies {
    /// Validates every CIDR (`10.0.0.0/8`, `fd00::/8`) or bare address.
    /// Host bits, out-of-range prefixes and IPv4-mapped IPv6 networks are
    /// rejected so configuration mistakes fail at startup.
    pub fn new<I, S>(cidrs: I, header: ForwardingHeader) -> Result<Self, ClientIpError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let networks = cidrs
            .into_iter()
            .map(|cidr| IpNetwork::parse(cidr.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { networks, header })
    }

    /// Parses a comma-separated list, ignoring blank entries.
    pub fn parse_list(raw: &str, header: ForwardingHeader) -> Result<Self, ClientIpError> {
        Self::new(
            raw.split(',').filter(|entry| !entry.trim().is_empty()),
            header,
        )
    }

    /// No proxy is trusted: the peer address is always the client.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    pub fn header(&self) -> ForwardingHeader {
        self.header
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(address))
    }

    pub fn resolve(&self, peer: IpAddr, headers: &ForwardingHeaders<'_>) -> IpAddr {
        self.resolve_with_source(peer, headers).0
    }

    pub fn resolve_with_source(
        &self,
        peer: IpAddr,
        headers: &ForwardingHeaders<'_>,
    ) -> (IpAddr, ClientIpSource) {
        let peer = normalize(peer);
        let fallback = (peer, ClientIpSource::Peer);
        if !self.contains(peer) {
            return fallback;
        }
        let Some(hops) = headers.hops_from_right(self.header) else {
            return fallback;
        };
        let mut leftmost_trusted = None;
        for (index, hop) in hops.into_iter().enumerate() {
            let Some(address) = hop else {
                return fallback;
            };
            if index == MAX_FORWARDED_HOPS {
                return fallback;
            }
            if !self.contains(address) {
                return (address, ClientIpSource::Header);
            }
            leftmost_trusted = Some(address);
        }
        leftmost_trusted.map_or(fallback, |address| (address, ClientIpSource::Header))
    }
}

/// Convenience wrapper around [`TrustedProxies::resolve`].
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &ForwardingHeaders<'_>,
    trusted: &TrustedProxies,
) -> IpAddr {
    trusted.resolve(peer, headers)
}

/// A trusted-proxy entry that failed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIpError {
    entry: String,
}

impl ClientIpError {
    fn invalid_network(entry: &str) -> Self {
        Self {
            entry: entry.trim().chars().take(64).collect(),
        }
    }
}

impl fmt::Display for ClientIpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid trusted proxy network {:?}: expected an IP address or a CIDR without host bits",
            self.entry
        )
    }
}

impl std::error::Error for ClientIpError {}

#[cfg(test)]
mod tests;
