//! Correct-by-construction reqwest clients.

use std::sync::Arc;

use reqwest::{ClientBuilder, Method};
use url::Url;

use super::request::GuardedRequest;
use super::{harden_guarded, harden_pinned};
use crate::net_guard::{NetGuard, NetGuardError, ResolvedTarget};

/// reqwest client whose every request URL is checked by the guard before it
/// is built. The inner client is not exposed, so no request can skip the
/// check.
#[derive(Clone, Debug)]
pub struct GuardedClient {
    guard: Arc<NetGuard>,
    client: reqwest::Client,
}

impl GuardedClient {
    /// Client with reqwest defaults plus the guard's settings.
    pub fn new(guard: Arc<NetGuard>) -> Result<Self, reqwest::Error> {
        Self::with_config(guard, |builder| builder)
    }

    /// Lets the caller configure timeouts, TLS, user agent... The guard's
    /// settings (resolver, redirect policy, no proxy, https-only) are
    /// applied afterwards and cannot be overridden by `configure`.
    pub fn with_config<F>(guard: Arc<NetGuard>, configure: F) -> Result<Self, reqwest::Error>
    where
        F: FnOnce(ClientBuilder) -> ClientBuilder,
    {
        let builder = configure(reqwest::Client::builder());
        let client = harden_guarded(builder, Arc::clone(&guard)).build()?;
        Ok(Self { guard, client })
    }

    /// The guard in use.
    pub fn guard(&self) -> &NetGuard {
        &self.guard
    }

    /// Checks `url` (scheme, credentials, port, literal address, localhost
    /// names) and returns a request builder for it.
    pub fn request(&self, method: Method, url: &Url) -> Result<GuardedRequest, NetGuardError> {
        self.guard.check_url(url)?;
        Ok(GuardedRequest::new(
            self.client.request(method, url.clone()),
        ))
    }

    /// `GET` shortcut for [`GuardedClient::request`].
    pub fn get(&self, url: &Url) -> Result<GuardedRequest, NetGuardError> {
        self.request(Method::GET, url)
    }

    /// `POST` shortcut for [`GuardedClient::request`].
    pub fn post(&self, url: &Url) -> Result<GuardedRequest, NetGuardError> {
        self.request(Method::POST, url)
    }
}

/// reqwest client pinned to one [`ResolvedTarget`]: it connects only to the
/// checked addresses and accepts only URLs with the target's host and port.
#[derive(Clone, Debug)]
pub struct PinnedClient {
    guard: Arc<NetGuard>,
    target: ResolvedTarget,
    client: reqwest::Client,
}

impl PinnedClient {
    /// Pinned client with reqwest defaults plus the guard's settings.
    pub fn new(guard: Arc<NetGuard>, target: ResolvedTarget) -> Result<Self, reqwest::Error> {
        Self::with_config(guard, target, |builder| builder)
    }

    /// Like [`GuardedClient::with_config`], pinned to `target`.
    pub fn with_config<F>(
        guard: Arc<NetGuard>,
        target: ResolvedTarget,
        configure: F,
    ) -> Result<Self, reqwest::Error>
    where
        F: FnOnce(ClientBuilder) -> ClientBuilder,
    {
        let builder = configure(reqwest::Client::builder());
        let client = harden_pinned(builder, Arc::clone(&guard), &target).build()?;
        Ok(Self {
            guard,
            target,
            client,
        })
    }

    /// The pinned target.
    pub fn target(&self) -> &ResolvedTarget {
        &self.target
    }

    /// Request to the pinned URL itself.
    pub fn request_target(&self, method: Method) -> GuardedRequest {
        GuardedRequest::new(self.client.request(method, self.target.url().clone()))
    }

    /// Request to another path on the pinned origin. `url` must pass the
    /// guard and have the target's host and port (default ports included).
    pub fn request(&self, method: Method, url: &Url) -> Result<GuardedRequest, NetGuardError> {
        self.guard.check_url(url)?;
        let expected = format!("{}:{}", self.target.host(), self.target.port());
        let host = url
            .host()
            .map(|host| match host {
                url::Host::Ipv6(ip) => ip.to_string(),
                other => other.to_string().to_ascii_lowercase(),
            })
            .unwrap_or_default();
        let actual = format!("{host}:{}", url.port_or_known_default().unwrap_or(0));
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(NetGuardError::TargetMismatch { expected, actual });
        }
        Ok(GuardedRequest::new(
            self.client.request(method, url.clone()),
        ))
    }
}
