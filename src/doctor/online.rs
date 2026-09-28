use super::channels::{smtp_ready, telegram_ready};
use super::{Check, CheckStatus, check};
use crate::config::RuntimeConfig;
use std::time::Duration;

pub(super) async fn online_checks(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            checks.push(check("HTTP client", CheckStatus::Error, error.to_string()));
            return;
        }
    };
    checks.push(
        http_probe(
            &client,
            "public health",
            format!("{}/healthz", cfg.public_url),
        )
        .await,
    );
    checks.push(
        http_probe(
            &client,
            "ntfy health",
            format!("{}/v1/health", cfg.ntfy_url),
        )
        .await,
    );
    telegram_check(cfg, &client, checks).await;
    smtp_check(cfg, checks).await;
}

async fn telegram_check(cfg: &RuntimeConfig, client: &reqwest::Client, checks: &mut Vec<Check>) {
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
        client.get(url).send().await,
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

async fn http_probe(client: &reqwest::Client, name: &str, url: String) -> Check {
    response_check(name, client.get(url).send().await)
}

fn response_check(name: &str, response: reqwest::Result<reqwest::Response>) -> Check {
    match response {
        Ok(response) if response.status().is_success() => {
            check(name, CheckStatus::Ok, response.status().to_string())
        }
        Ok(response) => check(name, CheckStatus::Error, response.status().to_string()),
        Err(error) => check(name, CheckStatus::Error, error.without_url().to_string()),
    }
}
