use crate::config::{NtfyTopic, RuntimeConfig};
use crate::inhibition::ack_sign;
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::strip_non_ascii;
use base64::{Engine as _, engine::general_purpose};
use std::time::Duration;

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
    let encoded_title = format!(
        "=?UTF-8?B?{}?=",
        general_purpose::STANDARD.encode(parts.title.as_bytes())
    );
    let actions_header = ntfy_actions(state, cfg, parts);
    let mut any_ok = false;
    for topic in topics {
        any_ok |= deliver_topic(
            state,
            cfg,
            NtfyRequest {
                parts,
                timeout_s,
                encoded_title: &encoded_title,
                actions: actions_header.as_deref(),
                topic: &topic,
            },
        )
        .await;
    }
    any_ok
}

fn ntfy_actions(state: &AppState, cfg: &RuntimeConfig, parts: &Parts) -> Option<String> {
    let confirmation_url = parts
        .emergency_ack_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .map(|token| format!("{}/emergency/{token}", cfg.public_url));
    let mut actions = parts
        .actions
        .iter()
        .filter(|[_, _, target]| {
            confirmation_url
                .as_deref()
                .is_none_or(|confirmation| target != confirmation)
        })
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let alertname = notification_alertname(parts);
    if !alertname.is_empty() && !parts.skip_snooze {
        let token = ack_sign(state, &alertname, cfg.ack_default_ttl);
        actions.push([
            "view".into(),
            "Snooze 1h".into(),
            format!("{}/api/ack/{token}", cfg.public_url),
        ]);
    }
    combine_actions(emergency_action(parts), regular_actions(&actions))
}

fn regular_actions(actions: &[[String; 3]]) -> Option<String> {
    (!actions.is_empty()).then(|| {
        actions
            .iter()
            .take(3)
            .map(|[kind, label, target]| format!("{kind}, {}, {target}", strip_non_ascii(label)))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn emergency_action(parts: &Parts) -> Option<String> {
    match (&parts.emergency_ack_url, &parts.emergency_ack_token) {
        (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => Some(format!(
            "http, Acknowledge, {url}, method=POST, headers.X-Klaxond-Emergency-Token={token}, clear=true"
        )),
        _ => None,
    }
}

fn combine_actions(emergency: Option<String>, regular: Option<String>) -> Option<String> {
    match (emergency, regular) {
        (Some(emergency), Some(regular)) => Some(format!("{emergency}; {regular}")),
        (Some(emergency), None) => Some(emergency),
        (None, regular) => regular,
    }
}

fn notification_alertname(parts: &Parts) -> String {
    let configured = parts.alertname.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }
    parts
        .title
        .split_once(" — ")
        .map_or(parts.title.as_str(), |(before, _)| before)
        .chars()
        .filter(|c| !c.is_ascii() || c.is_alphanumeric() || "-_./ ".contains(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

struct NtfyRequest<'a> {
    parts: &'a Parts,
    timeout_s: u64,
    encoded_title: &'a str,
    actions: Option<&'a str>,
    topic: &'a NtfyTopic,
}

async fn deliver_topic(state: &AppState, cfg: &RuntimeConfig, request: NtfyRequest<'_>) -> bool {
    let NtfyRequest {
        parts,
        timeout_s,
        encoded_title,
        actions,
        topic,
    } = request;
    if topic.token.is_empty() {
        tracing::warn!("ntfy: topic '{}' has no token", topic.name);
        return false;
    }
    let mut http_request = state
        .http
        .post(format!("{}/{}", cfg.ntfy_url, topic.name))
        .timeout(Duration::from_secs(timeout_s))
        .header("Authorization", format!("Bearer {}", topic.token))
        .header("Title", encoded_title)
        .header("Tags", parts.tags.join(","))
        .header("Priority", parts.priority.clone())
        .body(parts.body.clone());
    if let Some(actions) = actions {
        http_request = http_request.header("Actions", actions);
    }
    if let Some(sequence_id) = &parts.ntfy_sequence_id {
        http_request = http_request.header("X-Sequence-ID", sequence_id);
    }
    if let Some(attach) = &parts.attach_url {
        http_request = http_request.header("Attach", attach);
    }
    match http_request.send().await {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            tracing::warn!("ntfy POST to {} returned {}", topic.name, response.status());
            false
        }
        Err(error) => {
            tracing::warn!("ntfy POST to {} failed: {}", topic.name, error);
            false
        }
    }
}
