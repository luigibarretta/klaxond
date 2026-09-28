use super::object_scalar_cow;
use crate::config::RuntimeConfig;
use crate::parsers::{Action, action};
use crate::util::json_get_str;
use serde_json::Value;

pub(super) fn grafana_actions(
    payload: &Value,
    common_annotations: Option<&serde_json::Map<String, Value>>,
    component: &str,
    cfg: &RuntimeConfig,
) -> Vec<Action> {
    let mut actions = Vec::new();
    let runbook = object_scalar_cow(common_annotations, "runbook_url");
    if !runbook.is_empty() {
        actions.push(action("view", "📖 Runbook", &runbook));
    }
    if let Some([label, slug]) = cfg.component_dashboards.get(component) {
        actions.push(action(
            "view",
            &format!("📊 {label}"),
            &format!("{}{}", cfg.grafana_base, slug),
        ));
    }
    let rule_url = grafana_rule_url(payload);
    if !rule_url.is_empty() {
        actions.push(action("view", "View rule", &rule_url));
    }
    actions
}

fn grafana_rule_url(payload: &Value) -> String {
    payload
        .get("alerts")
        .and_then(Value::as_array)
        .and_then(|alerts| alerts.first())
        .and_then(|alert| alert.get("generatorURL"))
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| json_get_str(payload, "externalURL").to_string())
}

pub(super) fn grafana_render_target(
    component: &str,
    cfg: &RuntimeConfig,
) -> (Option<String>, Option<u64>) {
    if let Some((uid, panel)) = cfg.component_image.get(component) {
        return (Some(format!("/d/{uid}")), *panel);
    }
    if let Some([_, slug]) = cfg.component_dashboards.get(component) {
        return (Some(slug.clone()), None);
    }
    (None, None)
}
