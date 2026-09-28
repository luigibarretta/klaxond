use super::support::cfg;
use klaxond::parsers::parse_source;
use serde_json::json;

#[test]
fn beszel_authentik_and_pve_parsers_match_python_golden() {
    assert_beszel_parser();
    assert_authentik_parser();
    assert_pve_parser();
}

fn assert_beszel_parser() {
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
}

fn assert_authentik_parser() {
    let (_tmp, cfg) = cfg();
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
}

fn assert_pve_parser() {
    let (_tmp, cfg) = cfg();
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
        ["view", "🖥 Open Proxmox", "https://proxmox.example.test"]
    );
    assert_eq!(pve.alertname, "pve-vzdump");
    assert_eq!(pve.priority, "urgent");
}
