use klaxond::config::{NtfyTopic, Paths, load_runtime_config};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

pub fn temp_paths(tmp: &TempDir) -> Paths {
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

pub fn cfg() -> (TempDir, klaxond::config::RuntimeConfig) {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut cfg = load_runtime_config(&paths).unwrap();
    assert!(
        cfg.toml.get("render").is_some(),
        "default TOML did not load render section"
    );
    cfg.ntfy_topics = vec![
        NtfyTopic {
            name: "info-topic".into(),
            token: "tk_info".into(),
            handles: vec!["info".into()],
        },
        NtfyTopic {
            name: "warning-topic".into(),
            token: "tk_warn".into(),
            handles: vec!["warning".into()],
        },
        NtfyTopic {
            name: "critical-topic".into(),
            token: "tk_crit".into(),
            handles: vec!["critical".into()],
        },
    ];
    cfg.source_urls = HashMap::from([
        (
            "uptime-kuma".into(),
            "https://uptime.example.test/dashboard".into(),
        ),
        (
            "healthchecks".into(),
            "https://healthchecks.example.test/projects".into(),
        ),
        ("wud".into(), "https://wud.example.test".into()),
        ("pve".into(), "https://proxmox.example.test".into()),
        ("shelfmark".into(), "https://shelfmark.example.test".into()),
        ("prowlarr".into(), "https://prowlarr.example.test".into()),
        ("decypharr".into(), "https://decypharr.example.test".into()),
    ]);
    cfg.component_dashboards.insert(
        "host".into(),
        ["Logs (Loki)".into(), "/d/loki-cluster-logs".into()],
    );
    cfg.component_dashboards.insert(
        "ups".into(),
        ["UPS dashboard".into(), "/d/ups-overview".into()],
    );
    cfg.component_image
        .insert("host".into(), ("infra-cluster-overview".into(), Some(10)));
    (tmp, cfg)
}
