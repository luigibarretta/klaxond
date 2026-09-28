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
