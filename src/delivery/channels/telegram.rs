use crate::config::RuntimeConfig;
use crate::parsers::Parts;
use crate::state::AppState;
use crate::util::html_escape;
use serde_json::json;
use std::time::Duration;

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
    let mut payload = vec![
        ("chat_id".to_string(), cfg.tg_chat.clone()),
        ("parse_mode".to_string(), "HTML".into()),
        ("text".to_string(), message(severity, parts)),
        ("disable_web_page_preview".to_string(), "true".into()),
    ];
    if let Some(markup) = reply_markup(parts) {
        payload.push(("reply_markup".into(), markup));
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
        Ok(response) => response.status().is_success(),
        Err(error) => {
            tracing::warn!("telegram POST failed: {}", error.without_url());
            false
        }
    }
}

fn message(severity: &str, parts: &Parts) -> String {
    format!(
        "<b>{}</b>\nseverity: <code>{}</code>\n\n{}",
        html_escape(&parts.title),
        html_escape(severity),
        html_escape(&parts.body)
    )
}

fn reply_markup(parts: &Parts) -> Option<String> {
    if parts.actions.is_empty() {
        return None;
    }
    let buttons = parts
        .actions
        .iter()
        .take(5)
        .filter(|[_, _, target]| !target.is_empty())
        .map(|[_, label, target]| json!([{ "text": label, "url": target }]))
        .collect::<Vec<_>>();
    Some(json!({ "inline_keyboard": buttons }).to_string())
}
