use crate::config::RuntimeConfig;
use crate::parsers::Parts;
use crate::state::DedupItem;
use std::collections::{HashMap, HashSet};

pub(super) fn highest_severity(items: &[DedupItem]) -> String {
    fn rank(s: &str) -> i32 {
        match s {
            "critical" => 4,
            "warning" => 3,
            "info" => 2,
            "resolved" => 1,
            _ => 0,
        }
    }
    items
        .iter()
        .map(|i| i.severity.as_str())
        .max_by(|left, right| rank(left).cmp(&rank(right)).then_with(|| left.cmp(right)))
        .unwrap_or("info")
        .to_string()
}

pub(super) fn render_batch(
    cfg: &RuntimeConfig,
    source: &str,
    severity: &str,
    items: &[DedupItem],
) -> Parts {
    let state_emoji = cfg
        .icons
        .get(severity)
        .or_else(|| cfg.icons.get("info"))
        .cloned()
        .unwrap_or_else(|| "ℹ️".into());
    let source_label = source_label(source);
    let lines = grouped_lines(items);
    Parts {
        title: format!(
            "{state_emoji} {source_label}: {} grouped event{} ({} group{})",
            items.len(),
            if items.len() > 1 { "s" } else { "" },
            lines.len(),
            if lines.len() > 1 { "s" } else { "" }
        ),
        body: summarized_body(&lines),
        tags: vec![
            cfg.tag_prefixes
                .get(severity)
                .cloned()
                .unwrap_or_else(|| "bell".into()),
            source.into(),
            "grouped".into(),
        ],
        actions: vec![],
        priority: cfg
            .priorities
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "default".into()),
        alertname: String::new(),
        skip_snooze: false,
        render_slug: None,
        render_panel: None,
        render_instance: String::new(),
        attach_url: None,
        ntfy_sequence_id: None,
        emergency_ack_url: None,
        emergency_ack_token: None,
    }
}

fn source_label(source: &str) -> String {
    match source {
        "wud" => "WUD".to_string(),
        "shelfmark" => "Shelfmark".to_string(),
        "prowlarr" => "Prowlarr".to_string(),
        "decypharr" => "Decypharr".to_string(),
        _ => {
            let mut c = source.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        }
    }
}

fn grouped_lines(items: &[DedupItem]) -> Vec<String> {
    let mut groups: HashMap<String, Vec<&DedupItem>> = HashMap::new();
    for it in items {
        groups.entry(it.dedup_key.clone()).or_default().push(it);
    }
    let mut rows = groups.into_iter().collect::<Vec<_>>();
    rows.sort_by(|(left_key, left), (right_key, right)| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left_key.cmp(right_key))
    });
    let mut lines = Vec::new();
    for (_, gitems) in rows {
        let first = gitems
            .iter()
            .min_by_key(|item| (&item.parts.title, &item.parts.body))
            .expect("dedup groups are never empty");
        let first_title = first
            .parts
            .title
            .split_once(": ")
            .map(|(_, r)| r)
            .unwrap_or(&first.parts.title);
        let suffix = if gitems.len() > 1 {
            group_suffix(&gitems)
        } else {
            String::new()
        };
        lines.push(format!("• {first_title}{suffix}"));
    }
    lines
}

fn group_suffix(items: &[&DedupItem]) -> String {
    let mut seen = HashSet::new();
    let mut hosts = items
        .iter()
        .filter_map(|item| {
            item.common_labels
                .get("host")
                .or_else(|| item.common_labels.get("instance"))
                .cloned()
                .or_else(|| {
                    item.payload
                        .get("watcher")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned)
                })
        })
        .filter(|host| !host.is_empty() && seen.insert(host.clone()))
        .collect::<Vec<_>>();
    hosts.sort();
    if hosts.is_empty() {
        return format!(" — {} hosts", items.len());
    }
    let preview = hosts.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    format!(
        " — {} hosts ({}{})",
        items.len(),
        preview,
        if hosts.len() > 5 { "…" } else { "" }
    )
}

fn summarized_body(lines: &[String]) -> String {
    let mut body = lines
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > 20 {
        body.push_str(&format!("\n… +{} more", lines.len() - 20));
    }
    body
}
