use super::super::deliver;
use super::support::{http_response, sample_parts, spawn_http_once, test_state};
use crate::config::NtfyTopic;
use std::collections::HashMap;

#[tokio::test]
async fn successful_delivery_suppresses_identical_repeat_without_second_channel_call() {
    let (_tmp, state) = test_state();
    let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = base;
    cfg.ntfy_topics = vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "secret-token".into(),
        handles: vec!["warning".into()],
    }];
    let setting = cfg.dedup.get_mut("grafana").expect("grafana setting");
    setting.repeat_suppression_enabled = true;
    setting.repeat_window_s = 7_200;
    state.replace_config(cfg);

    let first = deliver(
        &state,
        "warning",
        sample_parts(),
        true,
        HashMap::new(),
        "grafana",
    )
    .await;
    assert_eq!(first, (true, "ntfy".to_string()));
    request_rx.await.expect("first ntfy request");

    let repeated = deliver(
        &state,
        "warning",
        sample_parts(),
        true,
        HashMap::new(),
        "grafana",
    )
    .await;
    assert_eq!(repeated, (true, "repeat-suppressed".to_string()));

    let recent = state.recent_repeat_suppressions(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].source, "grafana");
    assert_eq!(recent[0].suppressed_count, 1);
}

#[tokio::test]
async fn failed_delivery_releases_repeat_reservation_for_retry() {
    let (_tmp, state) = test_state();
    let mut cfg = state.cfg();
    cfg.ntfy_url = "http://127.0.0.1:9".to_string();
    cfg.ntfy_topics = vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "secret-token".into(),
        handles: vec!["warning".into()],
    }];
    let setting = cfg.dedup.get_mut("grafana").expect("grafana setting");
    setting.repeat_suppression_enabled = true;
    setting.repeat_window_s = 7_200;
    state.replace_config(cfg);

    let failed = deliver(
        &state,
        "warning",
        sample_parts(),
        false,
        HashMap::new(),
        "grafana",
    )
    .await;
    assert!(!failed.0);

    let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = base;
    state.replace_config(cfg);
    let retried = deliver(
        &state,
        "warning",
        sample_parts(),
        false,
        HashMap::new(),
        "grafana",
    )
    .await;

    assert_eq!(retried, (true, "ntfy".to_string()));
    request_rx.await.expect("retry ntfy request");
}
