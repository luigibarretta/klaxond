use crate::inhibition::ack_sign;
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::{html_escape, strip_non_ascii};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

pub async fn post_to_ntfy(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    let topics = cfg.topics_for(severity);
    if topics.is_empty() {
        tracing::warn!("ntfy: no topic handles severity '{}'", severity);
        return false;
    }
    let title_b64 = general_purpose::STANDARD.encode(parts.title.as_bytes());
    let encoded_title = format!("=?UTF-8?B?{title_b64}?=");
    let mut actions = parts.actions.iter().take(2).cloned().collect::<Vec<_>>();
    let mut alertname = parts.alertname.trim().to_string();
    if alertname.is_empty() {
        let mut t = parts.title.clone();
        if let Some((before, _)) = t.split_once(" — ") {
            t = before.to_string();
        }
        alertname = t
            .chars()
            .filter(|c| !c.is_ascii() || c.is_alphanumeric() || "-_./ ".contains(*c))
            .collect::<String>()
            .trim()
            .to_string();
    }
    if !alertname.is_empty() && !parts.skip_snooze {
        let tok = ack_sign(state, &alertname, cfg.ack_default_ttl);
        actions.push([
            "view".into(),
            "Snooze 1h".into(),
            format!("{}/api/ack/{tok}", cfg.public_url),
        ]);
    }
    let actions_header = if actions.is_empty() {
        None
    } else {
        Some(
            actions
                .iter()
                .take(3)
                .map(|[kind, label, target]| {
                    format!("{kind}, {}, {target}", strip_non_ascii(label))
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    let mut any_ok = false;
    for topic in topics {
        if topic.token.is_empty() {
            tracing::warn!("ntfy: topic '{}' has no token", topic.name);
            continue;
        }
        let url = format!("{}/{}", cfg.ntfy_url, topic.name);
        let mut req = state
            .http
            .post(&url)
            .timeout(Duration::from_secs(timeout_s))
            .header("Authorization", format!("Bearer {}", topic.token))
            .header("Title", encoded_title.clone())
            .header("Tags", parts.tags.join(","))
            .header("Priority", parts.priority.clone())
            .body(parts.body.clone());
        if let Some(actions) = &actions_header {
            req = req.header("Actions", actions);
        }
        if let Some(attach) = &parts.attach_url {
            req = req.header("Attach", attach);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => any_ok = true,
            Ok(resp) => tracing::warn!("ntfy POST to {} returned {}", topic.name, resp.status()),
            Err(err) => tracing::warn!("ntfy POST to {} failed: {}", topic.name, err),
        }
    }
    any_ok
}

pub async fn post_to_telegram(
    state: &AppState,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
    let cfg = state.cfg();
    if cfg.tg_token.is_empty() || cfg.tg_chat.is_empty() {
        return false;
    }
    let msg = format!(
        "<b>{}</b>\nseverity: <code>{}</code>\n\n{}",
        html_escape(&parts.title),
        html_escape(severity),
        html_escape(&parts.body)
    );
    let mut payload = vec![
        ("chat_id".to_string(), cfg.tg_chat),
        ("parse_mode".to_string(), "HTML".into()),
        ("text".to_string(), msg),
        ("disable_web_page_preview".to_string(), "true".into()),
    ];
    if !parts.actions.is_empty() {
        let buttons = parts
            .actions
            .iter()
            .take(5)
            .filter(|[_, _, target]| !target.is_empty())
            .map(|[_, label, target]| json!([{ "text": label, "url": target }]))
            .collect::<Vec<_>>();
        payload.push((
            "reply_markup".into(),
            json!({ "inline_keyboard": buttons }).to_string(),
        ));
    }
    let url = format!(
        "{}/bot{}/sendMessage",
        cfg.telegram_api_base.trim_end_matches('/'),
        cfg.tg_token
    );
    match state
        .http
        .post(url)
        .timeout(Duration::from_secs(timeout_s))
        .form(&payload)
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(err) => {
            tracing::warn!("telegram POST failed: {}", err.without_url());
            false
        }
    }
}

pub async fn post_to_smtp(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    if cfg.smtp_host.is_empty()
        || cfg.smtp_user.is_empty()
        || cfg.smtp_pass.is_empty()
        || cfg.smtp_to.is_empty()
    {
        return false;
    }
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
    let from = cfg.smtp_from.clone();
    let to = cfg.smtp_to.clone();
    let subject = format!("[{severity}] {}", parts.title);
    let host = cfg.smtp_host.clone();
    let port = cfg.smtp_port;
    let starttls = cfg.smtp_starttls;
    let user = cfg.smtp_user.clone();
    let pass = cfg.smtp_pass.clone();
    let fut = tokio::task::spawn_blocking(move || -> Result<()> {
        let email = Message::builder()
            .from(from.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;
        let creds = Credentials::new(user, pass);
        let builder = if starttls {
            SmtpTransport::starttls_relay(&host)?
        } else {
            SmtpTransport::builder_dangerous(&host)
        };
        let mailer = builder.port(port).credentials(creds).build();
        mailer.send(&email).context("smtp send")?;
        Ok(())
    });
    match timeout(Duration::from_secs(timeout_s), fut).await {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(err))) => {
            tracing::warn!("smtp send failed: {}", err);
            false
        }
        Ok(Err(err)) => {
            tracing::warn!("smtp task failed: {}", err);
            false
        }
        Err(_) => {
            tracing::warn!("smtp send timed out");
            false
        }
    }
}
