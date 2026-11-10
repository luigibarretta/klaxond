use super::channels::{smtp_ready, telegram_ready};
use super::{Check, CheckStatus, check};
use crate::config::RuntimeConfig;
use crate::outbound::{OutboundError, classify, outbound_guard};
use http_hardening::net_guard::reqwest_adapter::GuardedClient;
use reqwest::Url;
use std::sync::Arc;
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn online_checks(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    let client = match reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            checks.push(check("HTTP client", CheckStatus::Error, error.to_string()));
            return;
        }
    };
    // Klaxond's own public URL is not a delivery target: plain client.
    checks.push(response_check(
        "public health",
        client
            .get(format!("{}/healthz", cfg.public_url))
            .send()
            .await
            .map_err(OutboundError::Transport),
    ));
    let Some(guarded) = guarded_client(cfg, checks) else {
        return;
    };
    let ntfy_health = format!("{}/v1/health", cfg.ntfy_url);
    checks.push(response_check(
        "ntfy health",
        guarded_get(&guarded, &ntfy_health).await,
    ));
    telegram_check(cfg, &guarded, checks).await;
    smtp_check(cfg, checks).await;
}

/// Channel probes use the delivery guard, so a destination outside the
/// outbound allowlist is reported here exactly as a delivery would see it.
fn guarded_client(cfg: &RuntimeConfig, checks: &mut Vec<Check>) -> Option<GuardedClient> {
    let built = outbound_guard(&cfg.outbound_allowed_cidrs)
        .map_err(|error| format!("outbound allowlist is invalid: {error}"))
        .and_then(|guard| {
            GuardedClient::with_config(Arc::new(guard), |builder| builder.timeout(PROBE_TIMEOUT))
                .map_err(|error| error.to_string())
        });
    match built {
        Ok(client) => Some(client),
        Err(error) => {
            checks.push(check("outbound guard", CheckStatus::Error, error));
            None
        }
    }
}

async fn guarded_get(
    client: &GuardedClient,
    url: &str,
) -> Result<reqwest::Response, OutboundError> {
    let url =
        Url::parse(url).map_err(|error| OutboundError::Refused(format!("invalid URL: {error}")))?;
    let request = client
        .get(&url)
        .map_err(|error| OutboundError::Refused(error.to_string()))?;
    request.send().await.map_err(classify)
}

async fn telegram_check(cfg: &RuntimeConfig, client: &GuardedClient, checks: &mut Vec<Check>) {
    if !telegram_ready(cfg) {
        return;
    }
    let url = format!(
        "{}/bot{}/getMe",
        cfg.telegram_api_base.trim_end_matches('/'),
        cfg.tg_token
    );
    checks.push(response_check(
        "Telegram credentials",
        guarded_get(client, &url).await,
    ));
}

async fn smtp_check(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    if !smtp_ready(cfg) {
        return;
    }
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect((cfg.smtp_host.as_str(), cfg.smtp_port)),
    )
    .await;
    checks.push(match result {
        Ok(Ok(_)) => check(
            "SMTP connectivity",
            CheckStatus::Ok,
            "TCP connection accepted",
        ),
        Ok(Err(error)) => check("SMTP connectivity", CheckStatus::Error, error.to_string()),
        Err(_) => check(
            "SMTP connectivity",
            CheckStatus::Error,
            "TCP connection timed out",
        ),
    });
}

fn response_check(name: &str, response: Result<reqwest::Response, OutboundError>) -> Check {
    match response {
        Ok(response) if response.status().is_success() => {
            check(name, CheckStatus::Ok, response.status().to_string())
        }
        Ok(response) => check(name, CheckStatus::Error, response.status().to_string()),
        // OutboundError hides request URLs (the Telegram one carries the token).
        Err(error) => check(name, CheckStatus::Error, error.to_string()),
    }
}
