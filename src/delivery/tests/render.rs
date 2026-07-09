use super::super::render::{first_render_panel_from_dashboard, render_alert_image};
use super::support::{http_response, spawn_http_once, test_state};
use serde_json::json;

#[test]
fn first_panel_skips_non_renderable_dashboard_blocks() {
    let body = json!({
        "dashboard": {
            "panels": [
                { "id": 1, "type": "row", "panels": [
                    { "id": 2, "type": "text" },
                    { "id": 7, "type": "timeseries" }
                ]},
                { "id": 9, "type": "stat" }
            ]
        }
    });

    assert_eq!(first_render_panel_from_dashboard(&body), Some(7));
}

#[tokio::test]
async fn render_uses_fake_grafana_and_accepts_png() {
    let (_tmp, state) = test_state();
    let png = b"\x89PNG\r\n\x1a\nfake-png";
    let (base, request_rx) = spawn_http_once(http_response("image/png", png)).await;
    let mut cfg = state.cfg();
    cfg.grafana_render_base = base;
    cfg.grafana_render_token = "grafana-token".into();
    state.replace_config(cfg);
    let cfg = state.cfg();

    let rendered = render_alert_image(
        &state,
        &cfg,
        "/d/renderuid/node-overview",
        "host-a",
        Some(7),
    )
    .await
    .unwrap();
    let request = request_rx.await.unwrap();
    let lower = request.to_ascii_lowercase();

    assert_eq!(rendered, png);
    assert!(request.starts_with("GET /render/d-solo/renderuid/x?"));
    assert!(request.contains("panelId=7"));
    assert!(request.contains("var-instance=host-a"));
    assert!(lower.contains("authorization: bearer grafana-token"));
}
