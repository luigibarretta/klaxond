//! Startup check of the configured outbound targets, so a destination the
//! guard would refuse is reported before the first alert needs it.

use super::{OUTBOUND_ALLOWED_CIDRS_ENV, outbound_guard};
use crate::config::RuntimeConfig;
use crate::state::AppState;
use http_hardening::net_guard::NetGuard;
use reqwest::Url;

/// Gauge: 1 while a configured target is refused by the guard, else 0.
pub const TARGET_REFUSED_METRIC: &str = "klaxond_outbound_target_refused";

/// Configured targets as (label, base URL); empty values are skipped.
pub(crate) fn configured_targets(cfg: &RuntimeConfig) -> [(&'static str, &str); 3] {
    [
        ("ntfy", cfg.ntfy_url.as_str()),
        ("telegram", cfg.telegram_api_base.as_str()),
        ("grafana-render", cfg.grafana_render_base.as_str()),
    ]
}

/// Resolves every configured target once and records the verdict in
/// `klaxond_outbound_target_refused{target}`; refusals are logged at error
/// level with the setting that admits them. Returns the refused labels.
pub async fn check_configured_targets(state: &AppState) -> Vec<&'static str> {
    let cfg = state.cfg();
    let guard = match outbound_guard(&cfg.outbound_allowed_cidrs) {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!("{OUTBOUND_ALLOWED_CIDRS_ENV} is invalid: {error}");
            return Vec::new();
        }
    };
    let mut refused = Vec::new();
    for (label, base) in configured_targets(&cfg) {
        if base.trim().is_empty() || (label == "telegram" && cfg.tg_token.is_empty()) {
            continue;
        }
        let verdict = target_verdict(&guard, base).await;
        state.metric_set(
            TARGET_REFUSED_METRIC,
            &[("target", label)],
            f64::from(u8::from(verdict.is_err())),
        );
        if let Err(reason) = verdict {
            tracing::error!(
                target_name = label,
                "outbound target {label} is refused by the outbound guard ({reason}); deliveries \
                 through it will fail until its network is listed in {OUTBOUND_ALLOWED_CIDRS_ENV}"
            );
            refused.push(label);
        }
    }
    refused
}

/// Static URL check, then one DNS lookup judged like a delivery would be.
/// Resolver failures are not refusals: DNS may recover before delivery.
pub(crate) async fn target_verdict(guard: &NetGuard, base: &str) -> Result<(), String> {
    let url = Url::parse(base).map_err(|error| format!("invalid URL: {error}"))?;
    guard.check_url(&url).map_err(|error| error.to_string())?;
    let Some(host) = url.host_str() else {
        return Ok(());
    };
    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(0);
    let Ok(answer) = tokio::net::lookup_host((host, port)).await else {
        tracing::warn!("outbound target host {host} did not resolve at startup");
        return Ok(());
    };
    guard
        .check_addresses(host, port, answer)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
