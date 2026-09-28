use super::support::cfg;
use klaxond::parsers::parse_source;
use serde_json::json;

#[test]
fn github_issue_comment_parser_keeps_identity_context_and_action() {
    let (_tmp, cfg) = cfg();
    let (severity, github) = parse_source(
        "github",
        &json!({
            "event": "issue_comment",
            "repository": "owner/project",
            "issue_number": 42,
            "issue_title": "Concurrent client close can panic",
            "issue_url": "https://github.com/owner/project/issues/42",
            "comment_id": 1234,
            "comment_author": "maintainer",
            "comment_body": "Fixed on main and scheduled for the next release.",
            "comment_url": "https://github.com/owner/project/issues/42#issuecomment-1234"
        }),
        "info",
        &cfg,
    );
    assert_eq!(severity, "info");
    assert_eq!(
        github.title,
        "ℹ️ GitHub: owner/project#42 — reply from maintainer"
    );
    assert_eq!(
        github.body,
        "Concurrent client close can panic\n\nFixed on main and scheduled for the next release."
    );
    assert_eq!(
        github.tags,
        vec![
            "information_source",
            "info",
            "github",
            "speech_balloon",
            "github-analysis-enqueued"
        ]
    );
    assert_eq!(
        github.actions[0],
        [
            "view",
            "Open reply",
            "https://github.com/owner/project/issues/42#issuecomment-1234"
        ]
    );
    assert_eq!(github.alertname, "github-issue-comment");
    assert!(github.skip_snooze);
}

#[test]
fn revaulter_parser_keeps_approval_context_and_safe_action() {
    let (_tmp, mut cfg) = cfg();
    cfg.source_urls
        .insert("revaulter".into(), "https://revaulter.example.test".into());
    let (severity, revaulter) = parse_source(
        "revaulter",
        &json!({
            "event": "approval_required",
            "host": "it1-prd-nas-01",
            "summary": "A protected ZFS key request is waiting for passkey approval."
        }),
        "warning",
        &cfg,
    );
    assert_eq!(severity, "warning");
    assert_eq!(
        revaulter.title,
        "⚠️ Revaulter approval required — it1-prd-nas-01"
    );
    assert_eq!(
        revaulter.body,
        "A protected ZFS key request is waiting for passkey approval."
    );
    assert_eq!(
        revaulter.actions[0],
        ["view", "Open Revaulter", "https://revaulter.example.test"]
    );
    assert_eq!(revaulter.alertname, "revaulter-approval-required");
    assert!(revaulter.skip_snooze);
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
        ["view", "Open Shelfmark", "https://shelfmark.example.test"]
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
        ["view", "Open Decypharr", "https://decypharr.example.test"]
    );
    assert_eq!(decypharr.priority, "default");
    assert!(decypharr.skip_snooze);
}

#[test]
fn portable_defaults_omit_unconfigured_operator_links() {
    let (_tmp, mut cfg) = cfg();
    cfg.source_urls.clear();
    cfg.component_dashboards.clear();

    for (source, payload) in [
        ("pve", json!({"title": "Backup failed"})),
        ("healthchecks", json!({"check": "backup", "status": "down"})),
        ("uptime-kuma", json!({"heartbeat": {"status": 0}})),
        ("wud", json!({"title": "Update available"})),
        ("shelfmark", json!({"title": "Book", "type": "success"})),
        ("prowlarr", json!({"eventType": "Health"})),
        ("decypharr", json!({"event": "download_complete"})),
    ] {
        let (_, parts) = parse_source(source, &payload, "warning", &cfg);
        assert!(
            parts.actions.is_empty(),
            "{source} emitted an action without an operator-configured URL: {:?}",
            parts.actions
        );
    }
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
