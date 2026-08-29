use crate::config::RuntimeConfig;
use crate::inhibition::ack_sign;
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::{html_escape, strip_non_ascii};
use base64::{Engine as _, engine::general_purpose};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

pub async fn post_to_ntfy(state: &AppState, severity: &str, parts: &Parts, timeout_s: u64) -> bool {
    let cfg = state.cfg();
    post_to_ntfy_with_config(state, &cfg, severity, parts, timeout_s).await
}

pub(crate) async fn post_to_ntfy_with_config(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
    let topics = cfg.topics_for(severity);
    if topics.is_empty() {
        tracing::warn!("ntfy: no topic handles severity '{}'", severity);
        return false;
    }
    let title_b64 = general_purpose::STANDARD.encode(parts.title.as_bytes());
    let encoded_title = format!("=?UTF-8?B?{title_b64}?=");
    // Emergency receipts expose a native one-tap POST action on ntfy. The
    // signed web confirmation remains in `parts.actions` for Telegram and
    // SMTP, but showing both on ntfy creates two equivalent ACK buttons.
    let emergency_confirmation_url = parts
        .emergency_ack_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .map(|token| format!("{}/emergency/{token}", cfg.public_url));
    let mut actions = parts
        .actions
        .iter()
        .filter(|[_, _, target]| {
            emergency_confirmation_url
                .as_deref()
                .is_none_or(|confirmation| target != confirmation)
        })
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
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
    let emergency_action = match (&parts.emergency_ack_url, &parts.emergency_ack_token) {
        (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => Some(format!(
            "http, Acknowledge, {url}, method=POST, headers.X-Klaxond-Emergency-Token={token}, clear=true"
        )),
        _ => None,
    };
    let actions_header = match (emergency_action, actions_header) {
        (Some(emergency), Some(existing)) => Some(format!("{emergency}; {existing}")),
        (Some(emergency), None) => Some(emergency),
        (None, existing) => existing,
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
        if let Some(sequence_id) = &parts.ntfy_sequence_id {
            req = req.header("X-Sequence-ID", sequence_id);
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
    post_to_telegram_with_config(state, &cfg, severity, parts, timeout_s).await
}

pub(crate) async fn post_to_telegram_with_config(
    state: &AppState,
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
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
        ("chat_id".to_string(), cfg.tg_chat.clone()),
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
    post_to_smtp_with_config(&cfg, severity, parts, timeout_s).await
}

pub(crate) async fn post_to_smtp_with_config(
    cfg: &RuntimeConfig,
    severity: &str,
    parts: &Parts,
    timeout_s: u64,
) -> bool {
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
    let from = match cfg.smtp_from.parse() {
        Ok(address) => address,
        Err(err) => {
            tracing::warn!("invalid SMTP sender address: {err}");
            return false;
        }
    };
    let to = match cfg.smtp_to.parse() {
        Ok(address) => address,
        Err(err) => {
            tracing::warn!("invalid SMTP recipient address: {err}");
            return false;
        }
    };
    let email = match Message::builder()
        .from(from)
        .to(to)
        .subject(format!("[{severity}] {}", parts.title))
        .header(ContentType::TEXT_PLAIN)
        .body(body)
    {
        Ok(email) => email,
        Err(err) => {
            tracing::warn!("smtp message build failed: {err}");
            return false;
        }
    };
    let creds = Credentials::new(cfg.smtp_user.clone(), cfg.smtp_pass.clone());
    let builder = if cfg.smtp_starttls {
        match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host) {
            Ok(builder) => builder,
            Err(err) => {
                tracing::warn!("smtp transport build failed: {err}");
                return false;
            }
        }
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
    };
    let mailer = builder
        .port(cfg.smtp_port)
        .credentials(creds)
        .timeout(Some(Duration::from_secs(timeout_s)))
        .build();
    match timeout(Duration::from_secs(timeout_s), mailer.send(email)).await {
        Ok(Ok(_)) => true,
        Ok(Err(err)) => {
            tracing::warn!("smtp send failed: {}", err);
            false
        }
        Err(_) => {
            tracing::warn!("smtp send timed out");
            false
        }
    }
}
