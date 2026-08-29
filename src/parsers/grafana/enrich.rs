use super::beszel::{top_containers, top_containers_global, top_filesystems};
use crate::config::RuntimeConfig;
use regex::Regex;

pub(super) fn enrich_grafana_body(
    alertname: &str,
    host: &str,
    body: &str,
    cfg: &RuntimeConfig,
) -> Option<String> {
    let haystack = format!("{alertname} {body}");
    match matching_resource_kind(&haystack)? {
        "wan" => render_cluster_network(cfg),
        "disk" => render_filesystems(cfg, host),
        kind => render_host_consumers(cfg, host, kind),
    }
}

fn matching_resource_kind(haystack: &str) -> Option<&'static str> {
    for (pattern, kind) in resource_patterns() {
        if Regex::new(pattern).ok()?.is_match(haystack) {
            return Some(kind);
        }
    }
    Some("")
}

fn resource_patterns() -> [(&'static str, &'static str); 5] {
    [
        (
            r"(swap|ram|memory).*(high|pressure|exhausted|used|usage|above|averaged|\d+(\.\d+)?\s*%)",
            "mem",
        ),
        (r"(cpu|load(avg)?|load[\s_-]aver)", "cpu"),
        (
            r"network.*(high|saturation|bandwidth|saturated|\d+(\.\d+)?\s*%)",
            "net",
        ),
        (
            r"(disk|filesystem|fs|root|/pool|/dev/sd).*(full|high|low|usage|above|\d+(\.\d+)?\s*%)",
            "disk",
        ),
        (
            r"(internet|wan|icmp|blackbox).*(latency|slow|saturat|degrad|p\d+|loss)",
            "wan",
        ),
    ]
}

fn render_cluster_network(cfg: &RuntimeConfig) -> Option<String> {
    top_containers_global(cfg, "net", 5).map(|items| {
        if items.is_empty() {
            return String::new();
        }
        let mut lines = vec!["\nTop network consumers (cluster-wide):".to_string()];
        for (host, name, val, unit) in items {
            lines.push(format!("  • {name:20} @ {host:8} {val:>7.1}{unit}"));
        }
        lines.join("\n")
    })
}

fn render_filesystems(cfg: &RuntimeConfig, host: &str) -> Option<String> {
    if host.is_empty() {
        return Some(String::new());
    }
    top_filesystems(cfg, host, 5).map(|items| {
        if items.is_empty() {
            return String::new();
        }
        let mut lines = vec![format!("\nFilesystem usage ({host}):")];
        for (name, used, total, pct) in items {
            lines.push(format!(
                "  • {name:15} {used:>7.1}G / {total:>7.1}G  ({pct:>5.1}%)"
            ));
        }
        lines.join("\n")
    })
}

fn render_host_consumers(cfg: &RuntimeConfig, host: &str, kind: &str) -> Option<String> {
    if host.is_empty() || kind.is_empty() {
        return Some(String::new());
    }
    top_containers(cfg, host, kind, 3).map(|items| {
        if items.is_empty() {
            return String::new();
        }
        let mut lines = vec![format!("\nTop {} consumers ({host}):", metric_label(kind))];
        for (name, val, unit) in items {
            lines.push(format!("  • {name:25} {val:>7.1}{unit}"));
        }
        lines.join("\n")
    })
}

fn metric_label(kind: &str) -> &str {
    match kind {
        "mem" => "RAM",
        "cpu" => "CPU",
        "net" => "network",
        _ => kind,
    }
}
