use super::render::render_batch;
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
