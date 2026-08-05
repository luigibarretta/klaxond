use super::support::cfg;
use klaxond::parsers::parse_source;
use serde_json::json;

#[test]
fn beszel_authentik_and_pve_parsers_match_python_golden() {
    let (_tmp, cfg) = cfg();

    let (sev, beszel) = parse_source(
        "beszel",
        &json!({
            "alert": "CPU high",
            "system": "node-a",
            "value": 95,
            "threshold": 90,
            "url": "https://beszel.example/system/node-a"
        }),
        "warning",
        &cfg,
    );
    assert_eq!(sev, "warning");
    assert_eq!(beszel.title, "⚠️ Beszel: CPU high — node-a");
    assert_eq!(beszel.body, "value=95 (threshold=90)");
    assert_eq!(beszel.tags, vec!["warning", "warning", "beszel"]);
    assert_eq!(
        beszel.actions[0],
        [
            "view",
            "📊 Beszel UI",
            "https://beszel.example/system/node-a"
        ]
    );
    assert_eq!(beszel.priority, "high");
    assert!(!beszel.skip_snooze);

    let (sev, authentik) = parse_source(
        "authentik",
        &json!({
            "title": "Suspicious login",
            "message": "Denied login for luigi from 10.0.0.5",
            "data": {"severity": "critical", "host": "10.0.0.5"},
            "tags": ["auth"],
            "click": "https://auth.example/events/1",
            "actions": [
                {"label": "Open user", "url": "https://auth.example/users/luigi"}
            ]
        }),
        "info",
        &cfg,
    );
    assert_eq!(sev, "critical");
    assert_eq!(authentik.title, "🚨 Authentik: Suspicious login");
    assert_eq!(authentik.body, "Denied login for luigi from 10.0.0.5");
    assert_eq!(authentik.tags, vec!["rotating_light", "auth", "authentik"]);
    assert_eq!(
        authentik.actions[0],
        ["view", "Open Authentik", "https://auth.example/events/1"]
    );
    assert_eq!(
        authentik.actions[1],
        ["view", "Open user", "https://auth.example/users/luigi"]
    );
    assert_eq!(authentik.priority, "urgent");
    assert!(authentik.skip_snooze);

    let (_sev, pve) = parse_source(
        "pve",
        &json!({
            "title": "Backup failed",
            "message": "VM 101 backup failed",
            "node": "pve-01",
            "severity": "error",
            "type": "vzdump"
        }),
        "critical",
        &cfg,
    );
    assert_eq!(pve.title, "🚨 PVE pve-01: Backup failed");
    assert_eq!(
        pve.body,
        "Type: vzdump\nPVE severity: error\nVM 101 backup failed"
    );
    assert_eq!(pve.tags, vec!["rotating_light", "critical", "pve"]);
    assert_eq!(
        pve.actions[0],
        [
            "view",
            "🖥 Open Proxmox",
            "https://proxmox.luigibarretta.com/"
        ]
    );
    assert_eq!(pve.alertname, "pve-vzdump");
    assert_eq!(pve.priority, "urgent");
}

#[test]
fn uptime_kuma_parser_enriches_down_and_recovery_without_leaking_url_secrets() {
    let (_tmp, cfg) = cfg();
    let down_payload = json!({
        "msg": "[NAS API] [Down] Connection refused",
        "heartbeat": {
            "status": 0,
            "msg": "Connection refused",
            "ping": 0,
            "time": "2026-07-31 09:00:00"
        },
        "monitor": {
            "name": "NAS API",
            "type": "http",
            "url": "https://user:password@nas.example/health?token=secret"
        }
    });
    let (severity, down) = parse_source("uptime-kuma", &down_payload, "critical", &cfg);
    assert_eq!(severity, "critical");
    assert_eq!(down.title, "🚨 Kuma DOWN: NAS API");
    assert!(down.body.contains("Connection refused"));
    assert!(down.body.contains("Target: https://nas.example/health"));
    assert!(down.body.contains("Power correlation:"));
    assert!(!down.body.contains("password"));
    assert!(!down.body.contains("secret"));
    assert_eq!(down.priority, "urgent");
    assert!(!down.skip_snooze);
    assert_eq!(down.actions.len(), 2);

    let (severity, up) = parse_source(
        "uptime-kuma",
        &json!({
            "heartbeat": {"status": 1, "msg": "200 - OK", "ping": 8.4},
            "monitor": {"name": "NAS API", "type": "http", "url": "https://nas.example/health"}
        }),
        "critical",
        &cfg,
    );
    assert_eq!(severity, "resolved");
    assert_eq!(up.title, "✅ Kuma UP: NAS API");
    assert_eq!(up.priority, "low");
    assert!(up.skip_snooze);
    assert!(!up.body.contains("Power correlation:"));

    let (severity, notice) = parse_source(
        "uptime-kuma",
        &json!({
            "msg": "Domain name example.com will expire in 7 days"
        }),
        "critical",
        &cfg,
    );
    assert_eq!(severity, "warning");
    assert_eq!(notice.title, "⚠️ Kuma NOTICE: Uptime Kuma");
    assert!(notice.body.contains("example.com"));
    assert_eq!(notice.priority, "high");
    assert!(!notice.body.contains("Power correlation:"));
}

#[test]
fn shelfmark_and_decypharr_parsers_match_python_golden() {
    let (_tmp, cfg) = cfg();

    let (sev, shelfmark) = parse_source(
        "shelfmark",
        &json!({
            "title": "Import failed",
            "message": "Could not fetch metadata",
            "type": "failure",
            "user": "luigi"
        }),
        "info",
        &cfg,
    );
    assert_eq!(sev, "critical");
    assert_eq!(shelfmark.title, "🚨 Shelfmark: Import failed");
    assert_eq!(shelfmark.body, "Could not fetch metadata");
    assert_eq!(
        shelfmark.tags,
        vec!["rotating_light", "critical", "shelfmark", "book"]
    );
    assert_eq!(
        shelfmark.actions[0],
        ["view", "Open Shelfmark", "https://bookdl.luigibarretta.com"]
    );
    assert_eq!(shelfmark.priority, "urgent");
    assert!(shelfmark.skip_snooze);

    let (sev, decypharr) = parse_source(
        "decypharr",
        &json!({
            "event": "download_complete",
            "name": "Movie.mkv",
            "debrid": "realdebrid",
            "content_path": "/media/movies/Movie.mkv"
        }),
        "info",
        &cfg,
    );
    assert_eq!(sev, "info");
    assert_eq!(
        decypharr.title,
        "ℹ️ Decypharr: Download completed: Movie.mkv"
    );
    assert_eq!(
        decypharr.body,
        "Download completed: Movie.mkv\n-> /media/movies/Movie.mkv\n[backend: realdebrid]"
    );
    assert_eq!(
        decypharr.tags,
        vec!["information_source", "info", "decypharr", "download"]
    );
    assert_eq!(
        decypharr.actions[0],
        [
            "view",
            "Open Decypharr",
            "https://decypharr.luigibarretta.com"
        ]
    );
    assert_eq!(decypharr.priority, "default");
    assert!(decypharr.skip_snooze);
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
