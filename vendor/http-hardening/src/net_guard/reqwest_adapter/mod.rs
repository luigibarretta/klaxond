//! reqwest 0.12 adapters (feature `reqwest`).
//!
//! Use [`GuardedClient`] or [`PinnedClient`]: they are correct by
//! construction. Every request URL goes through [`NetGuard::check_url`]
//! first (scheme, credentials, port allowlist, literal addresses), which
//! matters because hyper's connector never calls the DNS resolver for a
//! literal IP host. DNS names are then checked by the resolver on every
//! connection, and every redirect hop by the redirect policy. Proxies are
//! disabled: a proxy would resolve the target itself and bypass the guard.
//!
//! The lower-level builders ([`client_builder_unchecked`],
//! [`pinned_client_builder`]) are for callers that need a raw
//! `reqwest::Client`; they leave the first URL unchecked.

mod client;
mod request;

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::{Attempt, Policy};
use reqwest::ClientBuilder;

use super::{NetGuard, NetGuardError, RedirectPolicy, ResolvedTarget, Scheme};

pub use client::{GuardedClient, PinnedClient};
pub use request::GuardedRequest;

/// Resolver that looks names up once per connection and refuses the answer
/// unless every address passes the guard. It sees no port: ports are
/// enforced by `check_url` (first request) and `check_redirect` (hops).
#[derive(Clone, Debug)]
pub struct GuardedResolver {
    guard: Arc<NetGuard>,
}

impl GuardedResolver {
    /// Wraps a shared guard.
    pub fn new(guard: Arc<NetGuard>) -> Self {
        Self { guard }
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = Arc::clone(&self.guard);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // The connector replaces the port with the URL's port.
            let answer = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|source| NetGuardError::Dns {
                    host: host.clone(),
                    source,
                })?;
            let addrs = guard.check_addresses(&host, 0, answer)?;
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// Resolver pinned to the addresses of one [`ResolvedTarget`]; any other
/// name fails, so a redirect to another host cannot trigger a fresh lookup.
#[derive(Clone, Debug)]
pub struct PinnedResolver {
    host: String,
    addrs: Vec<SocketAddr>,
}

impl PinnedResolver {
    /// Pins to the checked addresses of `target`.
    pub fn new(target: &ResolvedTarget) -> Self {
        Self {
            host: target.host().to_ascii_lowercase(),
            addrs: target.addrs().to_vec(),
        }
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let result = if name.as_str().eq_ignore_ascii_case(&self.host) {
            let addrs: Addrs = Box::new(self.addrs.clone().into_iter());
            Ok(addrs)
        } else {
            Err(NetGuardError::HostMismatch {
                expected: self.host.clone(),
                actual: name.as_str().to_owned(),
            }
            .into())
        };
        Box::pin(std::future::ready(result))
    }
}

/// reqwest redirect policy implementing the guard's [`RedirectPolicy`]:
/// `Policy::none()` when disabled, otherwise every hop is checked with
/// [`NetGuard::check_redirect`].
pub fn redirect_policy(guard: Arc<NetGuard>) -> Policy {
    match guard.redirect_policy() {
        RedirectPolicy::Disabled => Policy::none(),
        RedirectPolicy::Revalidate { .. } => {
            Policy::custom(move |attempt| check_attempt(&guard, attempt))
        }
    }
}

fn check_attempt(guard: &NetGuard, attempt: Attempt<'_>) -> reqwest::redirect::Action {
    let previous = attempt.previous();
    let followed = previous.len().saturating_sub(1);
    let verdict = match previous.last() {
        Some(from) => guard.check_redirect(from, attempt.url(), followed),
        None => Err(NetGuardError::MissingHost),
    };
    match verdict {
        Ok(()) => attempt.follow(),
        Err(error) => attempt.error(error),
    }
}

/// Applies the guard's settings last, so they win over anything `builder`
/// configured: no proxy, `https_only` unless HTTP is allowed, the redirect
/// policy and `resolver`.
fn harden<R: Resolve + 'static>(
    builder: ClientBuilder,
    guard: Arc<NetGuard>,
    resolver: Arc<R>,
) -> ClientBuilder {
    let https_only = !guard.allows_scheme(Scheme::Http);
    builder
        .no_proxy()
        .https_only(https_only)
        .dns_resolver(resolver)
        .redirect(redirect_policy(guard))
}

/// UNCHECKED: raw client builder with the guarded resolver and redirect
/// policy. A client built from it does not check the first request URL, so
/// a literal address (`http://10.0.0.1/`) reaches the network. Prefer
/// [`GuardedClient`]; otherwise call [`NetGuard::check_url`] before every
/// request.
/// Calling `.proxy()` on the returned builder re-enables proxying, and the
/// proxy then resolves targets instead of the guard.
#[doc(hidden)]
pub fn client_builder_unchecked(guard: Arc<NetGuard>) -> ClientBuilder {
    harden_guarded(reqwest::Client::builder(), guard)
}

/// Raw client builder pinned to `target` (from [`NetGuard::resolve`]). Send
/// requests only to `target.url()`: hyper-util replaces the pinned port with
/// the request URL's port, so a URL with another port would reach the
/// pinned address on an unchecked port. [`PinnedClient`] enforces this.
/// Calling `.proxy()` on the returned builder re-enables proxying and
/// bypasses the pinning.
#[doc(hidden)]
pub fn pinned_client_builder(guard: Arc<NetGuard>, target: &ResolvedTarget) -> ClientBuilder {
    harden_pinned(reqwest::Client::builder(), guard, target)
}

pub(crate) fn harden_guarded(builder: ClientBuilder, guard: Arc<NetGuard>) -> ClientBuilder {
    let resolver = Arc::new(GuardedResolver::new(Arc::clone(&guard)));
    harden(builder, guard, resolver)
}

pub(crate) fn harden_pinned(
    builder: ClientBuilder,
    guard: Arc<NetGuard>,
    target: &ResolvedTarget,
) -> ClientBuilder {
    harden(builder, guard, Arc::new(PinnedResolver::new(target)))
}
