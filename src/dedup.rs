mod key;
mod persistence;
mod render;

#[cfg(test)]
mod tests;

pub use self::key::dedup_key;
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

pub struct SubmitInput {
    pub source: String,
    pub severity: String,
    pub payload: Value,
    pub parts: Parts,
    pub common_labels: HashMap<String, String>,
    pub with_cascade: bool,
}

pub async fn submit(state: &AppState, input: SubmitInput) -> bool {
    let cfg = state.cfg();
    let source = input.source;
    let severity = input.severity;
    let Some(setting) = cfg.dedup.get(&source) else {
        return false;
    };
    if !setting.enabled || setting.strategy == "none" {
        return false;
    }
    if severity == "critical" && !setting.override_critical {
        return false;
    }
    let window = setting.window_s;
    let key = dedup_key(&source, &input.payload, &input.parts, &input.common_labels);
    let item = DedupItem {
        ts: now_epoch(),
        source: source.clone(),
        severity: severity.clone(),
        payload: input.payload,
        parts: input.parts,
        common_labels: input.common_labels,
        with_cascade: input.with_cascade,
        dedup_key: key,
    };
    {
        let mut d = state.dedup.lock().await;
        d.queues
            .entry(source.clone())
            .or_default()
            .push(item.clone());
        persist_item(state, &source, &item);
        if !d.timer_active.get(&source).copied().unwrap_or(false) {
            d.timer_active.insert(source.clone(), true);
            let state2 = state.clone();
            let source2 = source.clone();
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
