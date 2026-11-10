//! Anti-SSRF guard for outbound HTTP requests.
//!
//! Typical use for a webhook, ntfy server or OIDC discovery URL:
//!
//! 1. at configuration time, [`NetGuard::parse_url`] rejects bad schemes,
//!    embedded credentials, literal non-public addresses (in any encoding the
//!    WHATWG URL parser accepts: decimal, octal, hex, short IPv4 forms,
//!    IPv4-mapped/compatible IPv6, NAT64, 6to4, Teredo) and `localhost` names;
//! 2. at request time, [`NetGuard::resolve`] resolves DNS once, checks every
//!    address and returns them in a [`ResolvedTarget`] so the client connects
//!    to exactly those addresses (no second lookup, no DNS rebinding window);
//! 3. redirects are refused, or re-validated hop by hop
//!    ([`RedirectPolicy`]).
//!
//! An explicit CIDR allowlist ([`NetGuardBuilder::allow_cidr`]) admits
//! intended internal targets such as an ntfy server on the LAN. Unspecified,
//! multicast and broadcast addresses can never be allowlisted.

mod cidr;
mod error;
mod ip;
mod redirect;
mod resolve;

#[cfg(feature = "reqwest")]
pub mod reqwest_adapter;
#[cfg(feature = "ureq")]
pub mod ureq_adapter;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr};

use url::{Host, Url};

pub use cidr::{
    parse_cidr_list, Cidr, CidrError, MAX_CIDR_ENTRIES, MIN_IPV4_PREFIX, MIN_IPV6_PREFIX,
};
pub use error::NetGuardError;
pub use ip::{canonical_ip, classify, nat64_embedded_ipv4, AddressClass};
pub use redirect::{RedirectPolicy, MAX_REDIRECT_HOPS};
pub use resolve::{DnsLookup, ResolvedTarget, SystemDns, MAX_RESOLVED_ADDRESSES};

/// URL schemes a guard can allow. All are WHATWG "special" schemes, so the
/// URL parser canonicalises their IPv4 hosts in every obscure literal form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`
    Http,
    /// `https`
    Https,
    /// `ws`
    Ws,
    /// `wss`
    Wss,
}

impl Scheme {
    /// Lowercase scheme name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

/// Outbound request policy. Cheap to clone; share it behind an `Arc` with the
/// resolver adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetGuard {
    schemes: Vec<Scheme>,
    allow: Vec<Cidr>,
    ports: Option<Vec<u16>>,
    redirects: RedirectPolicy,
    max_addresses: usize,
}

impl Default for NetGuard {
    fn default() -> Self {
        Self::strict()
    }
}

impl NetGuard {
    /// HTTPS only, public addresses only, any port, redirects disabled.
    pub fn strict() -> Self {
        NetGuardBuilder::new().build()
    }

    /// Starts from the strict policy.
    pub fn builder() -> NetGuardBuilder {
        NetGuardBuilder::new()
    }

    /// Configured redirect policy.
    pub const fn redirect_policy(&self) -> RedirectPolicy {
        self.redirects
    }

    /// True when `scheme` is allowed.
    pub fn allows_scheme(&self, scheme: Scheme) -> bool {
        self.schemes.contains(&scheme)
    }

    /// Checks one address. Returns its canonical form (IPv4-mapped IPv6 is
    /// unwrapped) so callers connect to what was actually checked.
    pub fn check_ip(&self, ip: IpAddr) -> Result<IpAddr, NetGuardError> {
        let canonical = canonical_ip(ip);
        let class = classify(canonical);
        let allowed = !class.is_never_allowed()
            && (class.is_public() || self.allow.iter().any(|net| net.contains(canonical)));
        if allowed {
            Ok(canonical)
        } else {
            Err(NetGuardError::BlockedAddress { addr: ip, class })
        }
    }

    /// Checks a port against the allowlist; port 0 is always refused.
    pub fn check_port(&self, port: u16) -> Result<u16, NetGuardError> {
        let listed = self
            .ports
            .as_ref()
            .is_none_or(|ports| ports.contains(&port));
        if port == 0 || !listed {
            return Err(NetGuardError::PortNotAllowed(port));
        }
        Ok(port)
    }

    /// Parses `raw` with the WHATWG URL parser and runs [`NetGuard::check_url`].
    pub fn parse_url(&self, raw: &str) -> Result<Url, NetGuardError> {
        let url = Url::parse(raw.trim())?;
        self.check_url(&url)?;
        Ok(url)
    }

    /// Static checks that need no DNS: scheme, credentials, port, literal
    /// addresses and `localhost` names. DNS names are checked by
    /// [`NetGuard::resolve`] or by a resolver adapter.
    pub fn check_url(&self, url: &Url) -> Result<(), NetGuardError> {
        let scheme = url.scheme();
        if !self
            .schemes
            .iter()
            .any(|allowed| allowed.as_str() == scheme)
        {
            return Err(NetGuardError::SchemeNotAllowed(scheme.to_owned()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NetGuardError::CredentialsInUrl);
        }
        self.check_port(
            url.port_or_known_default()
                .ok_or(NetGuardError::MissingPort)?,
        )?;
        match url.host() {
            None => Err(NetGuardError::MissingHost),
            Some(Host::Ipv4(ip)) => self.check_ip(IpAddr::V4(ip)).map(drop),
            Some(Host::Ipv6(ip)) => self.check_ip(IpAddr::V6(ip)).map(drop),
            Some(Host::Domain(name)) => self.check_domain(name),
        }
    }

    /// Name-level checks. `localhost` and `*.localhost` always resolve to
    /// loopback (RFC 6761), so they are judged as `127.0.0.1` and pass only
    /// when loopback is allowlisted. Note: allowlisting `127.0.0.0/8` lets the
    /// name pass this static check, but `localhost` often also resolves to
    /// `::1`; since every address of an answer must pass, list `::1/128` too.
    fn check_domain(&self, name: &str) -> Result<(), NetGuardError> {
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.is_empty() || name.len() > 253 {
            return Err(NetGuardError::InvalidHost(name.to_owned()));
        }
        let lower = name.to_ascii_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") {
            return self.check_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)).map(drop);
        }
        Ok(())
    }
}

/// Builder for [`NetGuard`]; starts from the strict policy.
#[derive(Clone, Debug)]
pub struct NetGuardBuilder {
    guard: NetGuard,
}

impl Default for NetGuardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NetGuardBuilder {
    /// HTTPS only, no allowlist, any port, redirects disabled.
    pub fn new() -> Self {
        Self {
            guard: NetGuard {
                schemes: vec![Scheme::Https],
                allow: Vec::new(),
                ports: None,
                redirects: RedirectPolicy::Disabled,
                max_addresses: MAX_RESOLVED_ADDRESSES,
            },
        }
    }

    /// Adds an allowed scheme (e.g. [`Scheme::Http`] for a LAN ntfy server).
    pub fn allow_scheme(mut self, scheme: Scheme) -> Self {
        if !self.guard.schemes.contains(&scheme) {
            self.guard.schemes.push(scheme);
        }
        self
    }

    /// Admits a network that would otherwise be refused (private, loopback,
    /// link-local...). Use for intended internal targets only.
    ///
    /// Fails with [`CidrError::TooManyEntries`] past [`MAX_CIDR_ENTRIES`]
    /// distinct networks instead of silently dropping one.
    pub fn allow_cidr(mut self, cidr: Cidr) -> Result<Self, CidrError> {
        if self.guard.allow.contains(&cidr) {
            return Ok(self);
        }
        if self.guard.allow.len() >= MAX_CIDR_ENTRIES {
            return Err(CidrError::TooManyEntries);
        }
        self.guard.allow.push(cidr);
        Ok(self)
    }

    /// Adds every network of a list parsed with [`parse_cidr_list`] (prefixes
    /// shorter than /8 or /32 are refused).
    pub fn allow_cidr_list(self, raw: &str) -> Result<Self, CidrError> {
        parse_cidr_list(raw)?
            .into_iter()
            .try_fold(self, Self::allow_cidr)
    }

    /// Explicit opt-in for a wide network such as `0.0.0.0/0` or `fc00::/7`,
    /// parsed with [`Cidr::parse_wide`]. Review such entries carefully.
    pub fn allow_wide_cidr(self, raw: &str) -> Result<Self, CidrError> {
        self.allow_cidr(Cidr::parse_wide(raw)?)
    }

    /// Restricts destination ports (default: any non-zero port).
    pub fn allowed_ports(mut self, ports: &[u16]) -> Self {
        self.guard.ports = Some(ports.to_vec());
        self
    }

    /// Sets the redirect policy (default: disabled).
    pub fn redirects(mut self, policy: RedirectPolicy) -> Self {
        self.guard.redirects = match policy {
            RedirectPolicy::Revalidate { max_hops } => RedirectPolicy::revalidate(max_hops),
            RedirectPolicy::Disabled => RedirectPolicy::Disabled,
        };
        self
    }

    /// Maximum addresses accepted from one DNS answer, clamped to
    /// `1..=MAX_RESOLVED_ADDRESSES`.
    pub fn max_addresses(mut self, limit: usize) -> Self {
        self.guard.max_addresses = limit.clamp(1, MAX_RESOLVED_ADDRESSES);
        self
    }

    /// Finishes the guard.
    pub fn build(self) -> NetGuard {
        self.guard
    }
}
