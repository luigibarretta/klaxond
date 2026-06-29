use klaxond::config::NtfyTopic;
use klaxond::config::{Paths, load_runtime_config};
use klaxond::inhibition::{ack_match, ack_sign, ack_verify, apply_inhibition};
use klaxond::parsers::{
    normalize_labels, parse_grafana_payload, parse_healthchecks_payload, parse_source,
    parse_wud_payload,
};
use klaxond::state::AppState;
use serde_json::json;
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

fn cfg() -> (TempDir, klaxond::config::RuntimeConfig) {
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
    (tmp, cfg)
}

#[test]
fn grafana_parser_matches_python_golden() {
    let (_tmp, cfg) = cfg();
    let payload = json!({
        "status": "firing",
        "commonLabels": {
            "alertname": "HostLoadHigh",
            "severity": "critical",
            "component": "host",
            "host": "it1-prd-dev-01",
            "instance": "it1-prd-dev-01"
        },
        "commonAnnotations": {
            "summary": "load average above threshold",
            "description": "load1 has been high for 5m",
            "runbook_url": "https://docs.example/runbook"
        },
        "alerts": [{
            "labels": {"host": "it1-prd-dev-01"},
            "generatorURL": "https://grafana.example/rule/1"
        }]
    });

    let parts = parse_grafana_payload(&payload, "critical", &cfg);

    assert_eq!(parts.title, "🚨 Grafana: HostLoadHigh — it1-prd-dev-01");
    assert_eq!(
        parts.body,
        "load average above threshold\nload1 has been high for 5m"
    );
    assert_eq!(
        parts.tags,
        vec!["rotating_light", "critical", "grafana", "host"]
    );
    assert_eq!(parts.priority, "urgent");
    assert_eq!(parts.alertname, "HostLoadHigh");
    assert_eq!(
        parts.actions[0],
        ["view", "📖 Runbook", "https://docs.example/runbook"]
    );
    assert_eq!(
        parts.actions[1],
        [
            "view",
            "📊 Logs (Loki)",
            "https://grafana.luigibarretta.com/d/loki-cluster-logs"
        ]
    );
    assert_eq!(
        parts.actions[2],
        ["view", "View rule", "https://grafana.example/rule/1"]
    );
    assert_eq!(
        parts.render_slug.as_deref(),
        Some("/d/infra-cluster-overview")
    );
    assert_eq!(parts.render_panel, Some(10));
    assert!(!parts.skip_snooze);
}

#[test]
fn healthchecks_resolved_parser_matches_python_golden() {
    let (_tmp, cfg) = cfg();
    let payload = json!({
        "check": "backup-deadman",
        "status": "up",
        "code": "200",
        "last_ping": "2026-06-29T12:00:00Z",
        "tags": "host=nas-01 service=backup",
        "url": "https://hc.example/check"
    });

    let parts = parse_healthchecks_payload(&payload, "critical", &cfg);

    assert_eq!(parts.title, "✅ HC UP: backup-deadman");
    assert_eq!(
        parts.body,
        "Status: RESOLVED\nLast ping: 2026-06-29T12:00:00Z\nCode: 200\nTags: host=nas-01 service=backup"
    );
    assert_eq!(parts.tags, vec!["white_check_mark", "healthchecks"]);
    assert_eq!(parts.priority, "low");
    assert_eq!(
        parts.actions[0],
        ["view", "📊 Open in HC", "https://hc.example/check"]
    );
    assert!(parts.skip_snooze);
}

#[test]
fn wud_batch_parser_matches_python_golden() {
    let (_tmp, cfg) = cfg();
    let payload = json!([
        {"name":"grafana","watcher":"dev-01","updateKind":{"kind":"tag","localValue":"12.4.2","remoteValue":"13.1.0","semverDiff":"major"}},
        {"name":"loki","watcher":"dev-01","updateKind":{"kind":"tag","localValue":"3.5.0","remoteValue":"3.6.1"}}
    ]);

    let parts = parse_wud_payload(&payload, "info", &cfg);

    assert_eq!(parts.title, "ℹ️ WUD: 2 container updates available");
    assert_eq!(
        parts.body,
        "• grafana: tag 12.4.2 ⇒ 13.1.0 (major)\n• loki: tag 3.5.0 ⇒ 3.6.1"
    );
    assert_eq!(
        parts.tags,
        vec![
            "information_source",
            "info",
            "package",
            "wud",
            "container-update"
        ]
    );
    assert_eq!(
        parts.actions[0],
        ["view", "📦 Open WUD", "http://192.168.50.110:3033/"]
    );
    assert!(parts.skip_snooze);
}

#[test]
fn severity_overrides_match_python_sources() {
    let (_tmp, cfg) = cfg();

    let (sev, shelf) = parse_source(
        "shelfmark",
        &json!({"title":"Book","message":"Done","type":"failure"}),
        "info",
        &cfg,
    );
    assert_eq!(sev, "critical");
    assert_eq!(shelf.title, "🚨 Shelfmark: Book");

    let (sev, decy) = parse_source(
        "decypharr",
        &json!({"status":"failure","event":"download_fail","name":"Movie","message":"failed"}),
        "info",
        &cfg,
    );
    assert_eq!(sev, "warning");
    assert_eq!(decy.title, "⚠️ Decypharr: Download failed: Movie");

    let (sev, prow) = parse_source(
        "prowlarr",
        &json!({"eventType":"Health","health":{"type":"warning","message":"indexer unavailable"}}),
        "info",
        &cfg,
    );
    assert_eq!(sev, "warning");
    assert_eq!(prow.tags, vec!["warning", "warning", "prowlarr", "health"]);
}

#[test]
fn inhibition_order_and_ack_match_python() {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();

    let source_payload = json!({
        "status": "firing",
        "commonLabels": {"alertname":"NodeDown","inhibition_source":"node-down","host":"dev-01"}
    });
    let source_labels = normalize_labels("grafana", &source_payload);
    let (send, reason) = apply_inhibition(&state, "grafana", &source_labels, false);
    assert!(send);
    assert_eq!(reason, "source");

    let beszel_labels = normalize_labels("beszel", &json!({"alert":"CPU high","system":"dev-01"}));
    let (send, reason) = apply_inhibition(&state, "beszel", &beszel_labels, false);
    assert!(!send);
    assert_eq!(reason, "inhibited-by-node-down");

    let token = ack_sign(&state, "CPU high", 3600);
    let (alertname, why) = ack_verify(&state, &token);
    assert_eq!(why, "ok");
    assert_eq!(alertname.as_deref(), Some("CPU high"));
    klaxond::inhibition::register_ack_suppression(&state, "CPU high", 3600);
    let labels =
        std::collections::HashMap::from([("alertname".to_string(), "CPU high".to_string())]);
    assert_eq!(ack_match(&state, &labels).as_deref(), Some("CPU high"));
}
