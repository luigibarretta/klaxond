use super::super::deliver;
use super::support::{http_response, sample_parts, spawn_http_once, test_state};
use crate::config::{
    NoiseControlRule, NoiseMatchField, NoiseMatchOperator, NoiseRuleAction, NtfyTopic,
};
use crate::state::lock_mutex;
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

#[tokio::test]
async fn cascade_records_each_tier_and_returns_success_after_ntfy_failure() {
    let (_tmp, state) = test_state();
    let (telegram_base, telegram_request) =
        spawn_http_once(http_response("application/json", br#"{"ok":true}"#)).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = "http://127.0.0.1:9".to_string();
    cfg.ntfy_topics = vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "secret-token".into(),
        handles: vec!["warning".into()],
    }];
    cfg.telegram_api_base = telegram_base;
    cfg.tg_token = "bot-token".into();
    cfg.tg_chat = "chat-id".into();
    state.replace_config(cfg);

    let result = deliver(
        &state,
        "warning",
        sample_parts(),
        true,
        HashMap::from([("component".into(), "test-component".into())]),
        "grafana",
    )
    .await;

    assert_eq!(result, (true, "telegram".to_string()));
    telegram_request.await.expect("telegram fallback request");
    let counters = lock_mutex(&state.metrics.counters, "test metrics");
    assert_eq!(
        counters.get(
            "klaxond_delivery_tier_attempts_total|component=test-component,ok=0,severity=warning,source=grafana,tier=ntfy"
        ),
        Some(&1)
    );
    assert_eq!(
        counters.get(
            "klaxond_delivery_tier_attempts_total|component=test-component,ok=1,severity=warning,source=grafana,tier=telegram"
        ),
        Some(&1)
    );
}

#[tokio::test]
async fn selective_rule_suppresses_matching_repeat_when_source_default_is_disabled() {
    let (_tmp, state) = test_state();
    let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = base;
    cfg.ntfy_topics = vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "secret-token".into(),
        handles: vec!["warning".into()],
    }];
    cfg.dedup.get_mut("grafana").unwrap().rules = vec![NoiseControlRule {
        name: "Grafana test noise".into(),
        enabled: true,
        field: NoiseMatchField::Title,
        label: String::new(),
        operator: NoiseMatchOperator::Contains,
        pattern: "test alert".into(),
        case_sensitive: false,
        action: NoiseRuleAction::Suppress,
        cooldown_s: 21_600,
        include_critical: false,
    }];
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
    assert_eq!(recent[0].cooldown_s, 21_600);
    assert_eq!(
        recent[0].matched_rule.as_deref(),
        Some("Grafana test noise")
    );
}
