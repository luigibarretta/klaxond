use super::support::cfg;
use klaxond::parsers::{parse_grafana_payload, parse_healthchecks_payload, parse_wud_payload};
use serde_json::json;

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
fn grafana_grouped_alert_lists_per_instance_summaries() {
    let (_tmp, cfg) = cfg();
    let payload = json!({
        "status": "firing",
        "commonLabels": {
            "alertname": "Trivy — new running services with fixable CRITICAL CVE",
            "severity": "critical",
            "component": "security"
        },
        "commonAnnotations": {},
        "alerts": [
            {
                "labels": {"host": "it1-prd-dev-01", "service": "frontend"},
                "annotations": {
                    "summary": "frontend on it1-prd-dev-01 — app/frontend:v3 has 4 fixable CRITICAL CVEs"
                }
            },
            {
                "labels": {"host": "it1-prd-dns-01", "service": "wg-easy"},
                "annotations": {
                    "summary": "wg-easy on it1-prd-dns-01 — ghcr.io/wg-easy/wg-easy:15.3 has 1 fixable CRITICAL CVE"
                }
            }
        ]
    });

    let parts = parse_grafana_payload(&payload, "critical", &cfg);

    assert!(
        parts
            .body
            .contains("• frontend on it1-prd-dev-01 — app/frontend:v3 has 4 fixable CRITICAL CVEs")
    );
    assert!(parts.body.contains(
        "• wg-easy on it1-prd-dns-01 — ghcr.io/wg-easy/wg-easy:15.3 has 1 fixable CRITICAL CVE"
    ));
    assert!(
        parts
            .body
            .contains("Affected: it1-prd-dev-01, it1-prd-dns-01")
    );
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
