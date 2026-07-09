use super::super::config_admin::persist_reload;
use super::super::{json_body, json_response, text};
use crate::config::save_render_config;
use crate::parsers::{
    parse_beszel_payload, parse_grafana_payload, parse_healthchecks_payload, parse_wud_payload,
};
use crate::state::AppState;
use crate::util::toml_table_mut;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

pub(in crate::handlers) fn render_preview(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let severity = payload
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("warning")
        .to_string();
    let sample = payload.get("payload").cloned().unwrap_or_else(|| json!({}));
    let (parts, url) = state.with_cfg(|cfg| {
        let parts = if sample.get("alerts").is_some() || sample.get("commonLabels").is_some() {
            parse_grafana_payload(&sample, &severity, cfg)
        } else if sample.get("check").is_some() && sample.get("status").is_some() {
            parse_healthchecks_payload(&sample, &severity, cfg)
        } else if sample.get("title").is_some()
            && sample.get("body").is_some()
            && sample.get("alert").is_none()
        {
            parse_wud_payload(&sample, &severity, cfg)
        } else {
            parse_beszel_payload(&sample, &severity, cfg)
        };
        let url = cfg
            .ntfy_topics
            .iter()
            .find(|t| t.handles.iter().any(|h| h == &severity))
            .map(|t| format!("{}/{}", cfg.ntfy_url, t.name))
            .unwrap_or_else(|| format!("{}/(no topic handles '{}')", cfg.ntfy_url, severity));
        (parts, url)
    });
    let title_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        parts.title.as_bytes(),
    );
    json_response(json!({
        "url": url,
        "headers": {
            "Title (raw)": parts.title,
            "Title (RFC2047)": format!("=?UTF-8?B?{title_b64}?="),
            "Tags": parts.tags.join(","),
            "Priority": parts.priority,
            "Actions": parts.actions.iter().map(|[k,l,t]| format!("{k}, {l}, {t}")).collect::<Vec<_>>().join("; "),
        },
        "body": parts.body,
    }))
}

pub(in crate::handlers) fn update_render_config(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request = RenderConfigRequest::from_value(payload);
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let count = request.dashboard_count();
            if request.dashboards.present {
                if let Err(err) = save_render_config(&state.paths, &request.dashboards.cleaned) {
                    return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
                }
                cfg.component_dashboards = request.dashboards.cleaned.clone();
                toml_table_mut(&mut cfg.toml, &["render"]).insert(
                    "component_dashboards".into(),
                    dashboards_to_toml(&request.dashboards.cleaned),
                );
            }
            if let Some(settings) = request.settings {
                settings.apply_to(&mut cfg.toml);
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": count})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            if request.dashboards.present {
                return persist_reload(state, cfg.toml)
                    .map(|_| json_response(json!({"ok": true, "count": count})))
                    .unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "count": count}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

#[derive(Debug, Default)]
struct RenderConfigRequest {
    dashboards: DashboardPatch,
    settings: Option<RenderSettingsPatch>,
}

impl RenderConfigRequest {
    fn from_value(value: Value) -> Self {
        if !value.is_object() {
            return Self::default();
        }
        Self {
            dashboards: DashboardPatch::from_value(value.get("component_dashboards")),
            settings: RenderSettingsPatch::from_value(value.get("settings")),
        }
    }

    fn dashboard_count(&self) -> usize {
        self.dashboards.cleaned.len()
    }
}

#[derive(Debug, Default)]
struct DashboardPatch {
    present: bool,
    cleaned: HashMap<String, [String; 2]>,
}

impl DashboardPatch {
    fn from_value(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::default();
        };
        let cleaned = value
            .as_object()
            .map(clean_dashboards)
            .unwrap_or_else(HashMap::new);
        Self {
            present: true,
            cleaned,
        }
    }
}

fn clean_dashboards(raw: &serde_json::Map<String, Value>) -> HashMap<String, [String; 2]> {
    raw.iter()
        .filter_map(|(key, value)| clean_dashboard(key, value).map(|entry| (key.clone(), entry)))
        .collect()
}

fn clean_dashboard(key: &str, value: &Value) -> Option<[String; 2]> {
    let arr = value.as_array()?;
    let label = arr.first().and_then(Value::as_str).unwrap_or("");
    let url = arr.get(1).and_then(Value::as_str).unwrap_or("");
    if key.is_empty() || label.is_empty() || url.is_empty() {
        return None;
    }
    Some([label.to_string(), url.to_string()])
}

#[derive(Debug, Default, Deserialize)]
struct RenderSettingsPatch {
    #[serde(default, deserialize_with = "optional_string")]
    grafana_base: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    grafana_render_base: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    grafana_render_token: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    render_image_ttl: Option<u64>,
    #[serde(default, deserialize_with = "optional_string")]
    public_url: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    ack_default_ttl: Option<u64>,
}

impl RenderSettingsPatch {
    fn from_value(value: Option<&Value>) -> Option<Self> {
        let value = value.filter(|value| value.is_object())?;
        Some(serde_json::from_value(value.clone()).unwrap_or_default())
    }

    fn apply_to(self, toml: &mut toml::Value) {
        {
            let render = toml_table_mut(toml, &["render"]);
            if let Some(value) = self.grafana_base {
                render.insert(
                    "grafana_base".into(),
                    toml::Value::String(value.trim_end_matches('/').into()),
                );
            }
            if let Some(value) = self.grafana_render_base {
                render.insert(
                    "grafana_render_base".into(),
                    toml::Value::String(value.trim_end_matches('/').into()),
                );
            }
            if let Some(value) = self
                .grafana_render_token
                .filter(|value| value != "***SET***")
            {
                render.insert("grafana_render_token".into(), toml::Value::String(value));
            }
            if let Some(value) = self.render_image_ttl {
                render.insert(
                    "render_image_ttl".into(),
                    toml::Value::Integer(value.clamp(1, 86_400) as i64),
                );
            }
        }
        if let Some(value) = self.public_url {
            toml_table_mut(toml, &["server"]).insert(
                "public_url".into(),
                toml::Value::String(value.trim_end_matches('/').into()),
            );
        }
        if let Some(value) = self.ack_default_ttl {
            toml_table_mut(toml, &["acks"]).insert(
                "default_ttl_seconds".into(),
                toml::Value::Integer(value.clamp(60, 86_400) as i64),
            );
        }
    }
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

fn optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    })
}

fn dashboards_to_toml(dashboards: &HashMap<String, [String; 2]>) -> toml::Value {
    let mut table = toml::map::Map::new();
    let mut keys = dashboards.keys().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some([label, url]) = dashboards.get(key) {
            table.insert(
                key.clone(),
                toml::Value::Array(vec![
                    toml::Value::String(label.clone()),
                    toml::Value::String(url.clone()),
                ]),
            );
        }
    }
    toml::Value::Table(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_config_request_preserves_dashboard_cleaning_and_settings() {
        let request = RenderConfigRequest::from_value(json!({
            "component_dashboards": {
                "host": ["Host", "/d/host"],
                "bad-label": [42, "/d/bad"],
                "bad-url": ["Bad"],
                "not-array": { "label": "Ignored" },
                "": ["Empty", "/d/empty"]
            },
            "settings": {
                "grafana_base": "https://grafana.example.test///",
                "grafana_render_base": "https://render.example.test///",
                "grafana_render_token": "***SET***",
                "render_image_ttl": 999_999,
                "public_url": "https://klaxond.example.test///",
                "ack_default_ttl": 1
            }
        }));
        let mut toml = seed_toml();

        assert!(request.dashboards.present);
        assert_eq!(request.dashboard_count(), 1);
        assert_eq!(
            request.dashboards.cleaned.get("host"),
            Some(&["Host".to_string(), "/d/host".to_string()])
        );

        request
            .settings
            .expect("settings patch")
            .apply_to(&mut toml);

        assert_eq!(
            toml_str(&toml, &["render", "grafana_base"]),
            "https://grafana.example.test"
        );
        assert_eq!(
            toml_str(&toml, &["render", "grafana_render_base"]),
            "https://render.example.test"
        );
        assert_eq!(
            toml_str(&toml, &["render", "grafana_render_token"]),
            "old-render-token"
        );
        assert_eq!(toml_int(&toml, &["render", "render_image_ttl"]), 86_400);
        assert_eq!(
            toml_str(&toml, &["server", "public_url"]),
            "https://klaxond.example.test"
        );
        assert_eq!(toml_int(&toml, &["acks", "default_ttl_seconds"]), 60);
    }

    #[test]
    fn render_config_request_preserves_dashboard_presence_for_invalid_values() {
        let null_patch = RenderConfigRequest::from_value(json!({
            "component_dashboards": null
        }));
        let array_patch = RenderConfigRequest::from_value(json!({
            "component_dashboards": []
        }));
        let missing_patch = RenderConfigRequest::from_value(json!({}));

        assert!(null_patch.dashboards.present);
        assert!(null_patch.dashboards.cleaned.is_empty());
        assert!(array_patch.dashboards.present);
        assert!(array_patch.dashboards.cleaned.is_empty());
        assert!(!missing_patch.dashboards.present);
    }

    #[test]
    fn render_config_request_ignores_non_object_settings() {
        assert!(
            RenderConfigRequest::from_value(json!({"settings": []}))
                .settings
                .is_none()
        );
        assert!(
            RenderConfigRequest::from_value(json!({"settings": "bad"}))
                .settings
                .is_none()
        );
    }

    fn seed_toml() -> toml::Value {
        toml::from_str(
            r#"
[render]
grafana_base = "https://old-grafana.example.test/"
grafana_render_base = "https://old-render.example.test/"
grafana_render_token = "old-render-token"
render_image_ttl = 600

[server]
public_url = "https://old-klaxond.example.test/"

[acks]
default_ttl_seconds = 3600
"#,
        )
        .expect("seed toml")
    }

    fn toml_get<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
        let mut current = value;
        for key in path {
            current = current.as_table()?.get(*key)?;
        }
        Some(current)
    }

    fn toml_str<'a>(value: &'a toml::Value, path: &[&str]) -> &'a str {
        toml_get(value, path)
            .and_then(toml::Value::as_str)
            .expect("string value")
    }

    fn toml_int(value: &toml::Value, path: &[&str]) -> i64 {
        toml_get(value, path)
            .and_then(toml::Value::as_integer)
            .expect("integer value")
    }
}
