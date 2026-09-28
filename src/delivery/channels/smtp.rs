use crate::config::RuntimeConfig;
use crate::parsers::Parts;
use crate::state::AppState;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;
use tokio::time::timeout;

pub async fn post_to_smtp(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    post_to_smtp_with_config(&cfg, severity, parts, timeout_s).await
}

pub(crate) async fn post_to_smtp_with_config(
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
    if !smtp_configured(cfg) {
        return false;
    }
    let Some(email) = message(cfg, severity, parts) else {
        return false;
    };
    let Some(mailer) = transport(cfg, timeout_s) else {
        return false;
    };
    match timeout(Duration::from_secs(timeout_s), mailer.send(email)).await {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            tracing::warn!("smtp send failed: {}", error);
            false
        }
        Err(_) => {
            tracing::warn!("smtp send timed out");
            false
        }
    }
}

fn smtp_configured(cfg: &RuntimeConfig) -> bool {
    !cfg.smtp_host.is_empty()
        && !cfg.smtp_user.is_empty()
        && !cfg.smtp_pass.is_empty()
        && !cfg.smtp_to.is_empty()
}

fn message(cfg: &RuntimeConfig, severity: &str, parts: &Parts) -> Option<Message> {
    let mut body = format!("{}\n\nseverity: {severity}\n", parts.body);
    if !parts.actions.is_empty() {
        body.push('\n');
        body.push_str(
            &parts
                .actions
                .iter()
                .map(|[_, label, target]| format!("{label}: {target}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    let from = cfg
        .smtp_from
        .parse()
        .map_err(|error| {
            tracing::warn!("invalid SMTP sender address: {error}");
        })
        .ok()?;
    let to = cfg
        .smtp_to
        .parse()
        .map_err(|error| {
            tracing::warn!("invalid SMTP recipient address: {error}");
        })
        .ok()?;
    Message::builder()
        .from(from)
        .to(to)
        .subject(format!("[{severity}] {}", parts.title))
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|error| tracing::warn!("smtp message build failed: {error}"))
        .ok()
}

fn transport(cfg: &RuntimeConfig, timeout_s: u64) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
    let builder = if cfg.smtp_starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
            .map_err(|error| tracing::warn!("smtp transport build failed: {error}"))
            .ok()?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
    };
    Some(
        builder
            .port(cfg.smtp_port)
            .credentials(Credentials::new(
                cfg.smtp_user.clone(),
                cfg.smtp_pass.clone(),
            ))
            .timeout(Some(Duration::from_secs(timeout_s)))
            .build(),
    )
}
