//! ureq 2.x adapter (feature `ureq`).
//!
//! Use [`GuardedAgent`]. ureq's own redirect loop checks neither the scheme
//! nor the guard (it follows https to http downgrades unless `https_only` is
//! set), so the agent is built with `redirects(0)` and [`GuardedAgent`]
//! follows 3xx responses itself, running [`NetGuard::check_redirect`] on
//! every hop (hop limit, downgrade refusal, scheme, credentials, port,
//! literal address) before ureq resolves the next host through
//! [`UreqResolver`], which checks every DNS answer and literal address.
//!
//! Proxies: ureq resolves the *proxy* netloc, not the target, so a proxy
//! would bypass the guard. The agent is built with `try_proxy_from_env(false)`
//! (ureq reads `HTTP_PROXY` when any crate in the build enables its
//! `proxy-from-env` feature); never call `.proxy()` on a guarded builder.

mod agent;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::resolve::DnsLookup;
use super::{NetGuard, NetGuardError, Scheme, SystemDns};

pub use agent::{AgentOptions, GuardedAgent, GuardedCallError};

/// `ureq::Resolver` that checks every resolved address against the guard.
#[derive(Clone, Debug)]
pub struct UreqResolver {
    guard: Arc<NetGuard>,
}

impl UreqResolver {
    /// Wraps a shared guard.
    pub fn new(guard: Arc<NetGuard>) -> Self {
        Self { guard }
    }

    /// Resolves and checks a `host:port` netloc (IPv6 in brackets).
    pub fn resolve_netloc(&self, netloc: &str) -> Result<Vec<SocketAddr>, NetGuardError> {
        self.resolve_netloc_with(netloc, &SystemDns)
    }

    /// Like [`UreqResolver::resolve_netloc`] with a caller-supplied resolver.
    pub fn resolve_netloc_with<D>(
        &self,
        netloc: &str,
        dns: &D,
    ) -> Result<Vec<SocketAddr>, NetGuardError>
    where
        D: DnsLookup + ?Sized,
    {
        let invalid = || NetGuardError::InvalidHost(netloc.to_owned());
        let (host, port) = netloc.rsplit_once(':').ok_or_else(invalid)?;
        let port = port.parse::<u16>().map_err(|_| invalid())?;
        let port = self.guard.check_port(port)?;
        let bracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        if let Some(inner) = bracketed {
            let ip = inner.parse::<IpAddr>().map_err(|_| invalid())?;
            return self
                .guard
                .check_addresses(inner, port, [SocketAddr::new(ip, port)]);
        }
        if host.is_empty() || host.contains(':') {
            return Err(invalid());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self
                .guard
                .check_addresses(host, port, [SocketAddr::new(ip, port)]);
        }
        let answer = dns
            .lookup(host, port)
            .map_err(|source| NetGuardError::Dns {
                host: host.to_owned(),
                source,
            })?;
        self.guard.check_addresses(host, port, answer)
    }
}

impl ureq::Resolver for UreqResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        self.resolve_netloc(netloc).map_err(io::Error::from)
    }
}

/// UNCHECKED building block: agent builder with the validating resolver, no
/// proxy from the environment, `https_only` unless HTTP is allowed and
/// `redirects(0)`. Requests made on it are not checked by
/// [`NetGuard::check_url`] and redirects are not followed; prefer
/// [`GuardedAgent`]. Never call `.proxy()` on the result.
/// A `.proxy()` would be resolved instead of the target and bypass the guard.
#[doc(hidden)]
pub fn agent_builder_unchecked(guard: Arc<NetGuard>) -> ureq::AgentBuilder {
    let https_only = !guard.allows_scheme(Scheme::Http);
    ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .https_only(https_only)
        .redirects(0)
        .resolver(UreqResolver::new(guard))
}
