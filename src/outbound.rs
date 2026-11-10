//! Outbound HTTP for channel deliveries and their helpers (ntfy, Telegram,
//! Grafana rendering, channel health probes).
//!
//! Every request goes through `http_hardening::net_guard`: the URL is checked
//! before the request is built (scheme, credentials, port, literal and
//! encoded addresses, `localhost`), the resolver refuses a DNS answer that
//! contains any disallowed address and connects only to the checked
//! addresses, proxies are disabled and redirects are not followed (a 3xx is a
//! delivery failure, as before). Private, loopback, link-local and other
//! special-use destinations are refused unless the operator lists their
//! network in `KLAXOND_OUTBOUND_ALLOWED_CIDRS` / `[outbound].allowed_cidrs`.
//!
//! A refusal is never silent: the request fails like any transport error, so
//! the delivery tier is recorded as failed (audit ledger, tier metrics,
//! cascade to the next tier), and it is additionally logged at error level and
//! counted in `klaxond_outbound_refused_total{channel}`.

use crate::config::RuntimeConfig;
use crate::state::{AppState, lock_mutex};
use http_hardening::net_guard::reqwest_adapter::{GuardedClient, GuardedRequest};
use http_hardening::net_guard::{CidrError, NetGuard, NetGuardError, RedirectPolicy, Scheme};
use reqwest::{Method, Response, Url};
use std::fmt;
use std::sync::{Arc, Mutex};

mod preflight;
#[cfg(test)]
mod tests;

pub use preflight::check_configured_targets;

/// Env override of `[outbound].allowed_cidrs`.
pub const OUTBOUND_ALLOWED_CIDRS_ENV: &str = "KLAXOND_OUTBOUND_ALLOWED_CIDRS";
/// Counter of requests refused by the guard, labelled by channel.
pub const REFUSED_METRIC: &str = "klaxond_outbound_refused_total";
/// Upper bound of error sources inspected when classifying a failure.
const MAX_ERROR_DEPTH: usize = 16;

/// Guard for channel traffic: `http` and `https`, deny-private by default
/// plus the operator allowlist, redirects disabled.
pub fn outbound_guard(allowed_cidrs: &str) -> Result<NetGuard, CidrError> {
    Ok(NetGuard::builder()
        .allow_scheme(Scheme::Http)
        .allow_cidr_list(allowed_cidrs)?
        .redirects(RedirectPolicy::Disabled)
        .build())
}

/// Why an outbound request failed.
#[derive(Debug)]
pub enum OutboundError {
    /// The guard refused the destination (or the allowlist is invalid).
    Refused(String),
    /// The guarded client could not be built.
    Client(reqwest::Error),
    /// Connection, TLS, timeout or protocol failure.
    Transport(reqwest::Error),
}

impl OutboundError {
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `without_url`: Telegram URLs carry the bot token in their path.
        match self {
            Self::Refused(reason) => write!(f, "refused by the outbound guard: {reason}"),
            Self::Client(error) => write!(f, "HTTP client unavailable: {}", error_text(error)),
            Self::Transport(error) => write!(f, "{}", error_text(error)),
        }
    }
}

fn error_text(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    if let Some(url) = error.url() {
        text = text.replace(url.as_str(), "<url>");
    }
    text
}

/// Guarded clients cached per allowlist value, so a configuration reload that
/// changes the allowlist takes effect on the next delivery.
#[derive(Clone, Default)]
pub struct OutboundClients {
    cached: Arc<Mutex<Option<(String, GuardedClient)>>>,
}

impl OutboundClients {
    pub fn client(&self, allowed_cidrs: &str) -> Result<GuardedClient, OutboundError> {
        let mut cached = lock_mutex(&self.cached, "outbound client");
        if let Some((key, client)) = cached.as_ref()
            && key == allowed_cidrs
        {
            return Ok(client.clone());
        }
        let guard = outbound_guard(allowed_cidrs)
            .map_err(|error| OutboundError::Refused(format!("invalid allowlist: {error}")))?;
        let client = GuardedClient::new(Arc::new(guard)).map_err(OutboundError::Client)?;
        *cached = Some((allowed_cidrs.to_string(), client.clone()));
        Ok(client)
    }
}

/// One outbound request: the channel label used in logs and metrics, the
/// method and the absolute target URL.
pub struct Target<'a> {
    pub channel: &'static str,
    pub method: Method,
    pub url: &'a str,
}

/// Checks `target`, lets `build` add headers/body/timeout and sends the
/// request. Refusals are logged and counted here; callers log every error as
/// a failed attempt of their channel.
pub async fn send(
    state: &AppState,
    cfg: &RuntimeConfig,
    target: Target<'_>,
    build: impl FnOnce(GuardedRequest) -> GuardedRequest,
) -> Result<Response, OutboundError> {
    let result = prepare(state, cfg, &target).map(build);
    let result = match result {
        Ok(request) => request.send().await.map_err(classify),
        Err(error) => Err(error),
    };
    if let Err(error) = &result
        && error.is_refusal()
    {
        record_refusal(state, target.channel, error);
    }
    result
}

fn prepare(
    state: &AppState,
    cfg: &RuntimeConfig,
    target: &Target<'_>,
) -> Result<GuardedRequest, OutboundError> {
    let client = state.outbound.client(&cfg.outbound_allowed_cidrs)?;
    let url = Url::parse(target.url)
        .map_err(|error| OutboundError::Refused(format!("invalid URL: {error}")))?;
    client
        .request(target.method.clone(), &url)
        .map_err(|error| OutboundError::Refused(error.to_string()))
}

/// A send error caused by the guard's resolver (or redirect policy) is a
/// refusal; anything else is a transport failure.
pub(crate) fn classify(error: reqwest::Error) -> OutboundError {
    match guard_refusal(&error) {
        Some(reason) => OutboundError::Refused(reason),
        None => OutboundError::Transport(error),
    }
}

pub(crate) fn guard_refusal(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = Some(error);
    for _ in 0..MAX_ERROR_DEPTH {
        let candidate = current?;
        if let Some(refusal) = candidate.downcast_ref::<NetGuardError>() {
            return Some(refusal.to_string());
        }
        current = candidate.source();
    }
    None
}

fn record_refusal(state: &AppState, channel: &str, error: &OutboundError) {
    state.metric_inc(REFUSED_METRIC, &[("channel", channel)], 1);
    tracing::error!(
        channel,
        "outbound {channel} request {error}; if this destination is intended, add its network to \
         {OUTBOUND_ALLOWED_CIDRS_ENV} ([outbound].allowed_cidrs)"
    );
}
