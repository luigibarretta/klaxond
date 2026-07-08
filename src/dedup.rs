mod persistence;
mod render;

#[cfg(test)]
mod tests;

use self::persistence::{clear_persisted, pending_path, persist_item};
use self::render::{highest_severity, render_batch};
use crate::config::DEDUP_SOURCES;
use crate::delivery::deliver;
use crate::parsers::Parts;
use crate::state::{AppState, DedupItem};
use crate::util::now_epoch;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::time::Duration;

pub fn dedup_key(
    source: &str,
    payload: &Value,
    parts: &Parts,
    common_labels: &HashMap<String, String>,
) -> String {
    let title_fallback = if parts.title.is_empty() {
        "?"
    } else {
        &parts.title
    };
    match source {
        "wud" => {
            let p = payload
                .as_array()
                .and_then(|a| a.first())
                .unwrap_or(payload);
            if let Some(img) = p
                .get("image")
                .and_then(|i| i.get("name"))
                .and_then(|v| v.as_str())
                .or_else(|| p.get("name").and_then(|v| v.as_str()))
            {
                return format!("wud:{img}");
            }
        }
        "grafana" => {
            if let Some(an) = common_labels.get("alertname").filter(|s| !s.is_empty()) {
                return format!("grafana:{an}");
            }
        }
        "beszel" => {
            if let Some(cn) = payload
                .get("container_name")
                .and_then(|v| v.as_str())
                .or_else(|| common_labels.get("container_name").map(String::as_str))
            {
                return format!("beszel:{cn}");
            }
        }
        "healthchecks" => {
            if let Some(ck) = payload.get("name").and_then(|v| v.as_str()).or_else(|| {
                payload
                    .get("check")
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
            }) {
                return format!("hc:{ck}");
            }
        }
        "pve" => {
            if let Some(t) = payload
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                return format!("pve:{t}");
            }
        }
        "authentik" => {
            let data = payload.get("data").unwrap_or(&Value::Null);
            let user = data.get("user").and_then(|v| v.as_str()).unwrap_or("");
            let action = data
                .get("event")
                .or_else(|| data.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !user.is_empty() || !action.is_empty() {
                return format!("authentik:{action}:{user}");
            }
        }
        "shelfmark" => {
            let title = payload
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let evt = payload
                .get("event")
                .or_else(|| payload.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !title.is_empty() || !evt.is_empty() {
                return format!("shelfmark:{evt}:{title}");
            }
        }
        "prowlarr" => {
            let evt = payload
                .get("eventType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let health = payload.get("health").unwrap_or(&Value::Null);
            let msg = health
                .get("message")
                .or_else(|| payload.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .chars()
                .take(60)
                .collect::<String>();
            if !evt.is_empty() {
                return format!("prowlarr:{evt}:{msg}");
            }
        }
        "decypharr" => {
            let evt = payload
                .get("event")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let h = payload
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if !evt.is_empty() || !h.is_empty() {
                return format!("decypharr:{evt}:{h}");
            }
        }
        _ => {}
    }
    format!("{source}:{title_fallback}")
}

pub async fn submit(
    state: &AppState,
    source: &str,
    severity: &str,
    payload: Value,
    parts: Parts,
    common_labels: HashMap<String, String>,
    with_cascade: bool,
) -> bool {
    let cfg = state.cfg();
    let Some(setting) = cfg.dedup.get(source) else {
        return false;
    };
    if !setting.enabled || setting.strategy == "none" {
        return false;
    }
    if severity == "critical" && !setting.override_critical {
        return false;
    }
    let key = dedup_key(source, &payload, &parts, &common_labels);
    let item = DedupItem {
        ts: now_epoch(),
        source: source.to_string(),
        severity: severity.to_string(),
        payload,
        parts,
        common_labels,
        with_cascade,
        dedup_key: key,
    };
    {
        let mut d = state.dedup.lock().await;
        d.queues
            .entry(source.to_string())
            .or_default()
            .push(item.clone());
        persist_item(state, source, &item);
        if !d.timer_active.get(source).copied().unwrap_or(false) {
            d.timer_active.insert(source.to_string(), true);
            let state2 = state.clone();
            let source2 = source.to_string();
            let window = setting.window_s;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(window)).await;
                flush_source(&state2, &source2).await;
            });
        }
    }
    true
}

pub async fn restore_pending(state: &AppState) {
    let _ = fs::create_dir_all(&state.paths.dedup_pending_dir);
    for src in DEDUP_SOURCES {
        let path = pending_path(state, src);
        if !path.exists() {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let mut items = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if let Ok(item) = serde_json::from_str::<DedupItem>(line) {
                items.push(item);
            }
        }
        let _ = fs::remove_file(&path);
        if items.is_empty() {
            continue;
        }
        {
            let mut d = state.dedup.lock().await;
            d.queues.insert((*src).to_string(), items);
        }
        flush_source(state, src).await;
    }
}

pub async fn flush_all(state: &AppState) {
    for src in DEDUP_SOURCES {
        flush_source(state, src).await;
    }
}

pub async fn flush_source(state: &AppState, source: &str) {
    let items = {
        let mut d = state.dedup.lock().await;
        d.timer_active.insert(source.to_string(), false);
        let items = d
            .queues
            .entry(source.to_string())
            .or_default()
            .drain(..)
            .collect::<Vec<_>>();
        clear_persisted(state, source);
        items
    };
    if items.is_empty() {
        return;
    }
    let severity = highest_severity(&items);
    if items.len() == 1 {
        let it = items.into_iter().next().unwrap();
        let (ok, channel) = deliver(
            state,
            &severity,
            it.parts,
            it.with_cascade,
            it.common_labels,
            source,
        )
        .await;
        tracing::info!(
            "dedup[{}]: flushed 1 event -> {} via {}",
            source,
            if ok { "OK" } else { "FAIL" },
            channel
        );
        return;
    }
    let cfg = state.cfg();
    let parts = render_batch(&cfg, source, &severity, &items);
    let labels = items
        .first()
        .map(|i| i.common_labels.clone())
        .unwrap_or_default();
    let (ok, channel) = deliver(state, &severity, parts, true, labels, source).await;
    tracing::info!(
        "dedup[{}]: flushed {} events -> {} via {}",
        source,
        items.len(),
        if ok { "OK" } else { "FAIL" },
        channel
    );
}
