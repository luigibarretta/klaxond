use crate::config::RuntimeConfig;
use crate::state::AppState;
use serde_json::Value;
use std::time::Duration;

pub(super) async fn render_alert_image(
    state: &AppState,
    cfg: &RuntimeConfig,
    slug: &str,
    instance: &str,
    panel: Option<u64>,
) -> Option<Vec<u8>> {
    if cfg.grafana_render_base.is_empty()
        || cfg.grafana_render_token.is_empty()
        || slug.is_empty()
        || !slug.starts_with("/d/")
    {
        return None;
    }
    let uid = slug
        .trim_start_matches("/d/")
        .split(['/', '?'])
        .next()
        .unwrap_or("");
    let pid = match panel {
        Some(pid) => Some(pid),
        None => first_render_panel(state, cfg, uid).await,
    };
    let url = if let Some(pid) = pid {
        let mut params = vec![
            ("orgId", "1".to_string()),
            ("theme", "dark".into()),
            ("width", "1000".into()),
            ("height", "500".into()),
            ("panelId", pid.to_string()),
            ("from", "now-3h".into()),
            ("to", "now".into()),
        ];
        if !instance.is_empty() {
            params.push(("var-instance", instance.to_string()));
        }
        format!(
            "{}/render/d-solo/{}/x?{}",
            cfg.grafana_render_base,
            uid,
            serde_urlencoded(params)
        )
    } else {
        let mut params = vec![
            ("orgId", "1".to_string()),
            ("theme", "dark".into()),
            ("width", "1000".into()),
            ("height", "800".into()),
            ("from", "now-3h".into()),
            ("to", "now".into()),
        ];
        if !instance.is_empty() {
            params.push(("var-instance", instance.to_string()));
        }
        format!(
            "{}/render{}?{}",
            cfg.grafana_render_base,
            slug,
            serde_urlencoded(params)
        )
    };
    match state
        .http
        .get(url)
        .timeout(Duration::from_secs(25))
        .bearer_auth(&cfg.grafana_render_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let bytes = resp.bytes().await.ok()?.to_vec();
            if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                Some(bytes)
            } else {
                tracing::warn!("render: non-PNG response ({} bytes)", bytes.len());
                None
            }
        }
        Ok(resp) => {
            tracing::warn!("render: Grafana returned {}", resp.status());
            None
        }
        Err(err) => {
            tracing::warn!("render: failed: {}", err);
            None
        }
    }
}

async fn first_render_panel(state: &AppState, cfg: &RuntimeConfig, uid: &str) -> Option<u64> {
    if cfg.grafana_render_base.is_empty() || uid.is_empty() {
        return None;
    }
    let base = cfg.grafana_render_base.trim_end_matches('/');
    let url = format!("{}/api/dashboards/uid/{}", base, urlencoding::encode(uid));
    let resp = state
        .http
        .get(url)
        .timeout(Duration::from_secs(10))
        .bearer_auth(&cfg.grafana_render_token)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.json::<Value>().await.ok()?;
    first_render_panel_from_dashboard(&body)
}

pub(super) fn first_render_panel_from_dashboard(body: &Value) -> Option<u64> {
    let panels = body
        .get("dashboard")
        .and_then(|d| d.get("panels"))
        .and_then(Value::as_array)?;
    first_render_panel_in(panels)
}

fn first_render_panel_in(panels: &[Value]) -> Option<u64> {
    for panel in panels {
        let panel_type = panel.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(
            panel_type,
            "row" | "text" | "news" | "dashlist" | "alertlist"
        ) && let Some(id) = panel.get("id").and_then(Value::as_u64)
        {
            return Some(id);
        }
        if let Some(nested) = panel.get("panels").and_then(Value::as_array)
            && let Some(id) = first_render_panel_in(nested)
        {
            return Some(id);
        }
    }
    None
}

fn serde_urlencoded(params: Vec<(&str, String)>) -> String {
    params
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(&v)))
        .collect::<Vec<_>>()
        .join("&")
}
