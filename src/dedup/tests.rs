use super::dedup_key;
use super::render::{highest_severity, render_batch};
use crate::config::{Paths, load_runtime_config};
use crate::parsers::Parts;
use crate::state::DedupItem;
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
        history_db: data.join("klaxond.db"),
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
            ntfy_sequence_id: None,
            emergency_ack_url: None,
            emergency_ack_token: None,
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

#[test]
fn render_batch_orders_equal_groups_and_hosts_deterministically() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let cfg = load_runtime_config(&paths).unwrap();
    let mut zeta_a = item("Zeta: update");
    zeta_a.dedup_key = "zeta".into();
    zeta_a.common_labels.insert("host".into(), "node-z".into());
    let mut alpha_b = item("Alpha: update");
    alpha_b.dedup_key = "alpha".into();
    alpha_b.common_labels.insert("host".into(), "node-b".into());
    let mut zeta_b = zeta_a.clone();
    zeta_b.common_labels.insert("host".into(), "node-a".into());
    let mut alpha_a = alpha_b.clone();
    alpha_a.common_labels.insert("host".into(), "node-a".into());

    let rendered = render_batch(&cfg, "wud", "warning", &[zeta_a, alpha_b, zeta_b, alpha_a]);

    let alpha = rendered.body.find("• update — 2 hosts (node-a, node-b)");
    let zeta = rendered.body.find("• update — 2 hosts (node-a, node-z)");
    assert!(alpha.is_some_and(|alpha| zeta.is_some_and(|zeta| alpha < zeta)));
}

#[test]
fn render_batch_canonicalizes_titles_within_a_group() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let cfg = load_runtime_config(&paths).unwrap();
    let mut node_b = item("Alert: node-b is down");
    node_b.dedup_key = "grafana:HostDown".into();
    node_b.common_labels.insert("host".into(), "node-b".into());
    let mut node_a = item("Alert: node-a is down");
    node_a.dedup_key = node_b.dedup_key.clone();
    node_a.common_labels.insert("host".into(), "node-a".into());

    let forward = render_batch(
        &cfg,
        "grafana",
        "warning",
        &[node_b.clone(), node_a.clone()],
    );
    let reversed = render_batch(&cfg, "grafana", "warning", &[node_a, node_b]);

    assert_eq!(forward.title, reversed.title);
    assert_eq!(forward.body, reversed.body);
    assert!(forward.body.contains("node-a is down"));
}

#[test]
fn highest_severity_is_independent_of_batch_order() {
    let mut info = item("Info");
    info.severity = "info".into();
    let mut resolved = item("Resolved");
    resolved.severity = "resolved".into();

    assert_eq!(highest_severity(&[info.clone(), resolved.clone()]), "info");
    assert_eq!(highest_severity(&[resolved, info]), "info");
}

#[test]
fn uptime_kuma_dedup_key_is_stable_across_monitor_state_changes() {
    let parts = item("Monitor changed state").parts;
    let labels = HashMap::new();
    let down = json!({"monitor": {"id": 42, "name": "Public API"}, "heartbeat": {"status": 0}});
    let up = json!({"monitor": {"id": 42, "name": "Public API"}, "heartbeat": {"status": 1}});

    assert_eq!(
        dedup_key("uptime-kuma", &down, &parts, &labels),
        "uptime-kuma:42"
    );
    assert_eq!(
        dedup_key("uptime-kuma", &up, &parts, &labels),
        "uptime-kuma:42"
    );
}

#[test]
fn uptime_kuma_dedup_key_falls_back_to_monitor_name() {
    let parts = item("Monitor changed state").parts;
    let payload = json!({"monitor": {"name": " Public API "}});

    assert_eq!(
        dedup_key("uptime-kuma", &payload, &parts, &HashMap::new()),
        "uptime-kuma:Public API"
    );
}
