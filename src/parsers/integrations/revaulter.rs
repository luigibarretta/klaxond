use super::{EmptyStrExt, Parts, action};
use crate::config::RuntimeConfig;
use crate::parsers::Action;
use crate::util::json_get_str;
use serde_json::Value;

const SUMMARY_LIMIT: usize = 1_000;

fn bounded_summary(value: &str) -> String {
    let mut summary = value.chars().take(SUMMARY_LIMIT + 1).collect::<String>();
    if summary.chars().count() > SUMMARY_LIMIT {
        summary = summary.chars().take(SUMMARY_LIMIT).collect::<String>();
        summary.push_str("\n…");
    }
    summary
}

fn approval_action(cfg: &RuntimeConfig) -> Vec<Action> {
    cfg.source_url("revaulter")
        .map(|url| vec![action("view", "Open Revaulter", url)])
        .unwrap_or_default()
}

pub fn parse_revaulter_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let host = json_get_str(payload, "host").trim();
    let summary = bounded_summary(
        json_get_str(payload, "summary")
            .trim()
            .if_empty(
                "A protected-key request is waiting for passkey approval. Open Revaulter to inspect the operation and approve or reject it.",
            ),
    );
    let title_suffix = if host.is_empty() {
        String::new()
    } else {
        format!(" — {host}")
    };

    Parts {
        title: format!(
            "{} Revaulter approval required{title_suffix}",
            cfg.icon(severity)
        ),
        body: summary,
        tags: vec![
            cfg.tag_prefix(severity),
            severity.into(),
            "revaulter".into(),
            "key".into(),
        ],
        actions: approval_action(cfg),
        priority: cfg.priority(severity),
        alertname: "revaulter-approval-required".into(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Paths, load_runtime_config};
    use serde_json::json;
    use tempfile::TempDir;

    fn config() -> (TempDir, RuntimeConfig) {
        let dir = TempDir::new().unwrap();
        let paths = Paths {
            config: dir.path().join("klaxond.toml"),
            default_config: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("klaxond.default.toml"),
            render_config: dir.path().join("render.json"),
            ntfy_topics: dir.path().join("topics.json"),
            dedup_config: dir.path().join("dedup.json"),
            auth_config: dir.path().join("auth.json"),
            auth_session_key: dir.path().join("session.key"),
            backup_dir: dir.path().join("backups"),
            static_dir: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            dedup_pending_dir: dir.path().join("dedup_pending"),
            beszel_db: dir.path().join("beszel.db"),
            history_db: dir.path().join("history.db"),
        };
        let cfg = load_runtime_config(&paths).unwrap();
        (dir, cfg)
    }

    #[test]
    fn renders_safe_fallback_without_an_action_url() {
        let (_dir, cfg) = config();
        let parts = parse_revaulter_payload(
            &json!({"event": "approval_required", "host": "nas-01"}),
            "warning",
            &cfg,
        );
        assert_eq!(parts.title, "⚠️ Revaulter approval required — nas-01");
        assert!(parts.body.contains("waiting for passkey approval"));
        assert!(parts.actions.is_empty());
        assert!(parts.skip_snooze);
    }
}
