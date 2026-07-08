use super::{
    EmptyStrExt, EmptyStringExt, Parts, action, capitalize, first_non_empty, scalar_to_string,
};
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use serde_json::Value;

pub fn parse_wud_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let (title_raw, body_raw, extras) = if let Some(arr) = payload.as_array() {
        let count = arr.len();
        let mut lines = Vec::new();
        for c in arr.iter().take(10) {
            let name = json_get_str(c, "name").if_empty("?");
            let uk = c.get("updateKind").unwrap_or(&Value::Null);
            let local = json_get_str(uk, "localValue").if_empty("?");
            let remote = json_get_str(uk, "remoteValue").if_empty("?");
            let kind = json_get_str(uk, "kind").if_empty("tag");
            let semv = json_get_str(uk, "semverDiff");
            let sv = if semv.is_empty() {
                String::new()
            } else {
                format!(" ({semv})")
            };
            lines.push(format!("• {name}: {kind} {local} ⇒ {remote}{sv}"));
        }
        if count > 10 {
            lines.push(format!("… +{} more", count - 10));
        }
        (
            format!(
                "{count} container update{} available",
                if count != 1 { "s" } else { "" }
            ),
            lines.join("\n"),
            Value::Null,
        )
    } else if payload.is_object()
        && payload.get("name").is_some()
        && payload.get("updateKind").is_some()
    {
        let name = json_get_str(payload, "name").if_empty("?");
        let watcher = json_get_str(payload, "watcher").if_empty("local");
        let uk = payload.get("updateKind").unwrap_or(&Value::Null);
        let local = json_get_str(uk, "localValue").if_empty("?");
        let remote = json_get_str(uk, "remoteValue").if_empty("?");
        let kind = json_get_str(uk, "kind").if_empty("tag");
        let semv = json_get_str(uk, "semverDiff");
        let sv = if semv.is_empty() {
            String::new()
        } else {
            format!(" ({semv})")
        };
        let link = payload
            .get("result")
            .and_then(|r| r.get("link"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut body = format!("{name}: {kind} {local} ⇒ {remote}{sv}");
        if !link.is_empty() {
            body.push('\n');
            body.push_str(link);
        }
        (
            format!("Update available for {name} on {watcher}"),
            body,
            payload.clone(),
        )
    } else {
        (
            json_get_str(payload, "title")
                .if_empty("Container update available")
                .to_string(),
            json_get_str(payload, "body")
                .if_empty("Container update detected — see WUD UI for details.")
                .to_string(),
            payload.clone(),
        )
    };
    let rb = json_get_str(&extras, "runbook_url")
        .to_string()
        .if_empty_else(|| {
            cfg.fallback_runbooks
                .get("wud")
                .cloned()
                .unwrap_or_default()
        });
    let mut actions = Vec::new();
    if !rb.is_empty() {
        actions.push(action("view", "📖 Runbook", &rb));
    }
    actions.push(action(
        "view",
        "📦 Open WUD",
        json_get_str(&extras, "wud_url").if_empty("http://192.168.50.110:3033/"),
    ));
    Parts {
        title: format!("{} WUD: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags: vec![
            cfg.tag_prefix(severity),
            severity.into(),
            "package".into(),
            "wud".into(),
            "container-update".into(),
        ],
        actions,
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_authentik_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let title_raw = json_get_str(payload, "title").if_empty("Authentik notification");
    let body_raw = json_get_str(payload, "message").to_string();
    let mut tags = payload
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(scalar_to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    if !tags.iter().any(|t| t == "authentik") {
        tags.push("authentik".into());
    }
    let mut actions = Vec::new();
    if !json_get_str(payload, "click").is_empty() {
        actions.push(action(
            "view",
            "Open Authentik",
            json_get_str(payload, "click"),
        ));
    }
    if let Some(arr) = payload.get("actions").and_then(|v| v.as_array()) {
        for a in arr.iter().take(3) {
            if !json_get_str(a, "url").is_empty() && !json_get_str(a, "label").is_empty() {
                actions.push(action(
                    "view",
                    json_get_str(a, "label"),
                    json_get_str(a, "url"),
                ));
            }
        }
    }
    actions.truncate(3);
    Parts {
        title: format!("{} Authentik: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags,
        actions,
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_prowlarr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let evt = json_get_str(payload, "eventType").if_empty("Unknown");
    let instance = json_get_str(payload, "instanceName").if_empty("Prowlarr");
    let app_url =
        json_get_str(payload, "applicationUrl").if_empty("https://prowlarr.luigibarretta.com");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let health_message = first_non_empty(&[
        json_get_str(health, "message"),
        json_get_str(payload, "message"),
    ]);
    let health_wiki = first_non_empty(&[
        json_get_str(health, "wikiUrl"),
        json_get_str(payload, "wikiUrl"),
    ]);
    let (title_raw, body_raw, wiki) = match evt {
        "Health" => (
            "Health issue".to_string(),
            health_message.if_empty("Unknown health issue").to_string(),
            health_wiki.to_string(),
        ),
        "HealthRestored" => (
            "Health restored".to_string(),
            health_message
                .if_empty("All health issues resolved")
                .to_string(),
            String::new(),
        ),
        "ApplicationUpdate" => (
            "Application updated".to_string(),
            format!(
                "{} {} → {}",
                instance,
                json_get_str(payload, "previousVersion").if_empty("?"),
                json_get_str(payload, "newVersion").if_empty("?")
            ),
            String::new(),
        ),
        "Test" => (
            "Test notification".to_string(),
            "Klaxond webhook test successful".to_string(),
            String::new(),
        ),
        _ => (
            evt.to_string(),
            json_get_str(payload, "message").to_string(),
            String::new(),
        ),
    };
    let mut tags = vec![cfg.tag_prefix(severity), severity.into(), "prowlarr".into()];
    if evt == "Health" {
        tags.push("health".into());
    } else if evt == "ApplicationUpdate" {
        tags.push("update".into());
    } else if evt == "Test" {
        tags.push("test".into());
    }
    let mut actions = vec![action("view", "Open Prowlarr", app_url)];
    if !wiki.is_empty() {
        actions.push(action("view", "Wiki", &wiki));
    }
    Parts {
        title: format!("{} Prowlarr: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags,
        actions,
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_shelfmark_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let title_raw = json_get_str(payload, "title").if_empty("Shelfmark notification");
    let body_raw = json_get_str(payload, "message").to_string();
    let mut tags = vec![
        cfg.tag_prefix(severity),
        severity.into(),
        "shelfmark".into(),
        "book".into(),
    ];
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    Parts {
        title: format!("{} Shelfmark: {title_raw}", cfg.icon(severity)),
        body: body_raw,
        tags,
        actions: vec![action(
            "view",
            "Open Shelfmark",
            "https://bookdl.luigibarretta.com",
        )],
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn parse_decypharr_payload(payload: &Value, severity: &str, cfg: &RuntimeConfig) -> Parts {
    let event = json_get_str(payload, "event").trim().to_ascii_lowercase();
    let name = json_get_str(payload, "name")
        .if_empty("<unknown>")
        .trim()
        .to_string();
    let debrid = json_get_str(payload, "debrid").trim().to_string();
    let content_path = json_get_str(payload, "content_path").trim().to_string();
    let msg = json_get_str(payload, "message").trim().to_string();
    let event_human = match event.as_str() {
        "download_start" => "Download started".to_string(),
        "download_complete" => "Download completed".to_string(),
        "download_fail" | "download_failed" => "Download failed".to_string(),
        "download_error" => "Download error".to_string(),
        "" => "Event".to_string(),
        _ => capitalize(&event.replace('_', " ")),
    };
    let mut body = if !msg.is_empty() {
        msg
    } else {
        let mut bp = vec![format!("{event_human}: {name}")];
        if !content_path.is_empty() {
            bp.push(format!("-> {content_path}"));
        }
        bp.join("\n")
    };
    if !debrid.is_empty()
        && !body
            .to_ascii_lowercase()
            .contains(&debrid.to_ascii_lowercase())
    {
        body.push_str(&format!("\n[backend: {debrid}]"));
    }
    let mut tags = vec![
        cfg.tag_prefix(severity),
        severity.into(),
        "decypharr".into(),
        "download".into(),
    ];
    let sev_tag = cfg.tag_prefix(severity);
    if !tags.contains(&sev_tag) {
        tags.insert(0, sev_tag);
    }
    Parts {
        title: format!("{} Decypharr: {event_human}: {name}", cfg.icon(severity)),
        body,
        tags,
        actions: vec![action(
            "view",
            "Open Decypharr",
            "https://decypharr.luigibarretta.com",
        )],
        priority: cfg.priority(severity),
        alertname: String::new(),
        skip_snooze: true,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
    }
}

pub fn shelfmark_severity(payload: &Value, fallback: &str, cfg: &RuntimeConfig) -> String {
    let mapped = match json_get_str(payload, "type").to_ascii_lowercase().as_str() {
        "info" | "success" => Some("info"),
        "warning" => Some("warning"),
        "failure" => Some("critical"),
        _ => None,
    };
    mapped
        .filter(|s| cfg.known_severities().iter().any(|k| k == *s))
        .unwrap_or(fallback)
        .to_string()
}

pub fn prowlarr_severity(payload: &Value, fallback: &str) -> String {
    let evt = json_get_str(payload, "eventType");
    let health = payload.get("health").unwrap_or(&Value::Null);
    let ht = json_get_str(health, "type").to_ascii_lowercase();
    if evt == "Health" {
        if ht == "warning" {
            return "warning".into();
        }
        if matches!(ht.as_str(), "error" | "critical") {
            return "critical".into();
        }
    } else if matches!(evt, "HealthRestored" | "Test" | "ApplicationUpdate") {
        return "info".into();
    }
    fallback.to_string()
}

pub fn decypharr_severity(payload: &Value, fallback: &str, cfg: &RuntimeConfig) -> String {
    let mapped = match json_get_str(payload, "status")
        .to_ascii_lowercase()
        .as_str()
    {
        "success" => Some("info"),
        "failure" => Some("warning"),
        "error" => Some("critical"),
        _ => None,
    };
    mapped
        .filter(|s| cfg.known_severities().iter().any(|k| k == *s))
        .unwrap_or(fallback)
        .to_string()
}
