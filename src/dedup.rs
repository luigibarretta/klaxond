use crate::config::{DEDUP_SOURCES, RuntimeConfig};
use crate::delivery::deliver;
use crate::parsers::Parts;
use crate::state::{AppState, DedupItem};
use crate::util::now_epoch;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
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

fn highest_severity(items: &[DedupItem]) -> String {
    fn rank(s: &str) -> i32 {
        match s {
            "critical" => 2,
            "warning" => 1,
            _ => 0,
        }
    }
    items
        .iter()
        .map(|i| i.severity.as_str())
        .max_by_key(|s| rank(s))
        .unwrap_or("info")
        .to_string()
}

fn render_batch(cfg: &RuntimeConfig, source: &str, severity: &str, items: &[DedupItem]) -> Parts {
    let state_emoji = cfg
        .icons
        .get(severity)
        .or_else(|| cfg.icons.get("info"))
        .cloned()
        .unwrap_or_else(|| "ℹ️".into());
    let src_label = match source {
        "wud" => "WUD".to_string(),
        "shelfmark" => "Shelfmark".to_string(),
        "prowlarr" => "Prowlarr".to_string(),
        "decypharr" => "Decypharr".to_string(),
        _ => {
            let mut c = source.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        }
    };
    let mut groups: HashMap<String, Vec<&DedupItem>> = HashMap::new();
    for it in items {
        groups.entry(it.dedup_key.clone()).or_default().push(it);
    }
    let mut rows = groups.into_iter().collect::<Vec<_>>();
    rows.sort_by_key(|(_, g)| std::cmp::Reverse(g.len()));
    let mut lines = Vec::new();
    for (_, gitems) in rows {
        let first = gitems[0];
        let first_title = first
            .parts
            .title
            .split_once(": ")
            .map(|(_, r)| r)
            .unwrap_or(&first.parts.title);
        if gitems.len() == 1 {
            lines.push(format!("• {first_title}"));
        } else {
            let mut hosts = Vec::new();
            let mut seen = HashSet::new();
            for it in &gitems {
                let h = it
                    .common_labels
                    .get("host")
                    .or_else(|| it.common_labels.get("instance"))
                    .cloned()
                    .or_else(|| {
                        it.payload
                            .get("watcher")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .unwrap_or_default();
                if !h.is_empty() && seen.insert(h.clone()) {
                    hosts.push(h);
                }
            }
            let suffix = if hosts.is_empty() {
                format!(" — {} hosts", gitems.len())
            } else {
                let preview = hosts.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                format!(
                    " — {} hosts ({}{})",
                    gitems.len(),
                    preview,
                    if hosts.len() > 5 { "…" } else { "" }
                )
            };
            lines.push(format!("• {first_title}{suffix}"));
        }
    }
    let mut body = lines
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > 20 {
        body.push_str(&format!("\n… +{} more", lines.len() - 20));
    }
    Parts {
        title: format!(
            "{state_emoji} {src_label}: {} grouped event{} ({} group{})",
            items.len(),
            if items.len() > 1 { "s" } else { "" },
            lines.len(),
            if lines.len() > 1 { "s" } else { "" }
        ),
        body,
        tags: vec![
            cfg.tag_prefixes
                .get(severity)
                .cloned()
                .unwrap_or_else(|| "bell".into()),
            source.into(),
            "grouped".into(),
        ],
        actions: vec![],
        priority: cfg
            .priorities
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "default".into()),
        alertname: String::new(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

fn pending_path(state: &AppState, source: &str) -> std::path::PathBuf {
    state
        .paths
        .dedup_pending_dir
        .join(format!("pending_{source}.jsonl"))
}

fn persist_item(state: &AppState, source: &str, item: &DedupItem) {
    let _ = fs::create_dir_all(&state.paths.dedup_pending_dir);
    let path = pending_path(state, source);
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", serde_json::to_string(item).unwrap_or_default());
        }
        Err(err) => tracing::warn!("dedup: failed to persist {} item: {}", source, err),
    }
}

fn clear_persisted(state: &AppState, source: &str) {
    let _ = fs::remove_file(pending_path(state, source));
}

#[cfg(test)]
mod tests {
    use super::{DedupItem, render_batch};
    use crate::config::{Paths, load_runtime_config};
    use crate::parsers::Parts;
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_paths(tmp: &TempDir) -> Paths {
        let data = tmp.path();
        Paths {
            config: data.join("klaxond.toml"),
            default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
            render_config: data.join("render-config.json"),
            ntfy_topics: data.join("ntfy-topics.json"),
            dedup_config: data.join("dedup-config.json"),
            dedup_pending_dir: data.join("dedup_pending"),
            auth_config: data.join("auth-config.json"),
            auth_session_key: data.join("auth-session.key"),
            backup_dir: data.join("backups"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            beszel_db: data.join("missing-beszel.db"),
        }
    }

    fn item(title: &str) -> DedupItem {
        DedupItem {
            ts: 0.0,
            source: "wud".into(),
            severity: "warning".into(),
            payload: json!({"watcher": "node-a"}),
            parts: Parts {
                title: title.into(),
                body: String::new(),
                tags: vec![],
                actions: vec![],
                priority: String::new(),
                alertname: String::new(),
                skip_snooze: false,
                render_slug: None,
                render_panel: None,
                render_instance: String::new(),
                attach_url: None,
            },
            common_labels: HashMap::new(),
            with_cascade: true,
            dedup_key: title.into(),
        }
    }

    #[test]
    fn render_batch_uses_runtime_severity_render_config() {
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        let mut cfg = load_runtime_config(&paths).unwrap();
        cfg.icons.insert("warning".into(), "WARN".into());
        cfg.tag_prefixes
            .insert("warning".into(), "custom_warn".into());
        cfg.priorities.insert("warning".into(), "min".into());

        let parts = render_batch(&cfg, "wud", "warning", &[item("image-a"), item("image-b")]);

        assert!(parts.title.starts_with("WARN WUD: 2 grouped events"));
        assert_eq!(parts.tags, vec!["custom_warn", "wud", "grouped"]);
        assert_eq!(parts.priority, "min");
    }
}
