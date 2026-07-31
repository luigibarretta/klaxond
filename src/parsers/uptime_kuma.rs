use super::{Parts, action, scalar_to_string};
use crate::config::RuntimeConfig;
use serde_json::Value;
use url::Url;

const KUMA_URL: &str = "https://uptime.luigibarretta.com/dashboard";
const POWER_DASHBOARD_URL: &str = "https://grafana.luigibarretta.com/d/ups-ecoflow-overview";

pub fn parse_uptime_kuma_payload(
    payload: &Value,
    route_severity: &str,
    cfg: &RuntimeConfig,
) -> (String, Parts) {
    let heartbeat = payload.get("heartbeat").unwrap_or(&Value::Null);
    let monitor = payload.get("monitor").unwrap_or(&Value::Null);
    let status = heartbeat.get("status").and_then(Value::as_i64);
    let severity = match status {
        Some(1) => "resolved",
        Some(2 | 3) => "info",
        Some(0) => route_severity,
        _ => route_severity,
    }
    .to_string();
    let state = match status {
        Some(0) => "DOWN",
        Some(1) => "UP",
        Some(2) => "PENDING",
        Some(3) => "MAINTENANCE",
        _ => "NOTICE",
    };
    let name = monitor
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Uptime Kuma");
    let title = format!("{} Kuma {state}: {name}", cfg.icon(&severity));

    let mut body = Vec::new();
    if let Some(message) = heartbeat
        .get("msg")
        .and_then(Value::as_str)
        .or_else(|| payload.get("msg").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.push(message.to_string());
    }
    if let Some(target) = monitor_target(monitor) {
        body.push(format!("Target: {target}"));
    }
    if let Some(kind) = monitor
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        body.push(format!("Monitor type: {kind}"));
    }
    if let Some(ping) = heartbeat.get("ping").and_then(Value::as_f64) {
        body.push(format!("Latency: {ping:.0} ms"));
    }
    if let Some(time) = heartbeat
        .get("time")
        .map(scalar_to_string)
        .filter(|value| !value.is_empty())
    {
        body.push(format!("Observed: {time}"));
    }
    if status == Some(0) {
        body.push(
            "Power correlation: check the Power & UPS timeline before treating multiple simultaneous failures as independent incidents."
                .into(),
        );
    }
    if body.is_empty() {
        body.push(format!("Status: {state}"));
    }

    let tags = if severity == "resolved" {
        vec![cfg.tag_prefix("resolved"), "uptime-kuma".into()]
    } else {
        vec![
            cfg.tag_prefix(&severity),
            severity.clone(),
            "uptime-kuma".into(),
        ]
    };
    let priority = if severity == "resolved" {
        "low".into()
    } else {
        cfg.priority(&severity)
    };
    (
        severity,
        Parts {
            title,
            body: body.join("\n"),
            tags,
            actions: vec![
                action("view", "📈 Open Uptime Kuma", KUMA_URL),
                action("view", "🔋 Power & UPS", POWER_DASHBOARD_URL),
            ],
            priority,
            alertname: format!("uptime-kuma-{name}"),
            skip_snooze: status == Some(1),
            render_slug: None,
            render_panel: None,
            render_instance: String::new(),
            attach_url: None,
        },
    )
}

fn monitor_target(monitor: &Value) -> Option<String> {
    if let Some(raw) = monitor
        .get("url")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Some(sanitize_url(raw));
    }
    let host = monitor
        .get("hostname")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if host.is_empty() {
        return None;
    }
    let port = monitor
        .get("port")
        .map(scalar_to_string)
        .unwrap_or_default();
    Some(if port.is_empty() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    })
}

fn sanitize_url(raw: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw) else {
        return "configured URL".into();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::sanitize_url;

    #[test]
    fn target_url_drops_credentials_query_and_fragment() {
        assert_eq!(
            sanitize_url("https://user:secret@example.test/health?token=secret#debug"),
            "https://example.test/health"
        );
        assert_eq!(sanitize_url("not a url"), "configured URL");
    }
}
