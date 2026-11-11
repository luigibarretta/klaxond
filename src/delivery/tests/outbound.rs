//! Outbound guard on channel deliveries: refusals fail the tier visibly and
//! the cascade still delivers through the next channel.

use super::super::channels::{post_to_ntfy, post_to_telegram};
use super::super::deliver;
use super::support::{
    LOOPBACK_ALLOWLIST, counter, guarded_test_state, http_response, sample_parts, spawn_http_once,
};
use crate::config::NtfyTopic;
use crate::outbound::REFUSED_METRIC;
use std::collections::HashMap;

fn ntfy_topic() -> Vec<NtfyTopic> {
    vec![NtfyTopic {
        name: "warning-topic".into(),
        token: "secret-token".into(),
        handles: vec!["warning".into()],
    }]
}

#[tokio::test]
async fn ntfy_to_a_loopback_target_is_refused_without_an_allowlist() {
    let (_tmp, state) = guarded_test_state("");
    let (base, mut request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = base;
    cfg.ntfy_topics = ntfy_topic();
    state.replace_config(cfg);

    assert!(!post_to_ntfy(&state, "warning", &sample_parts(), 2).await);
    assert!(request_rx.try_recv().is_err(), "the guard must not connect");
    assert_eq!(counter(&state, REFUSED_METRIC, &["channel=ntfy"]), 1);
}

#[tokio::test]
async fn ntfy_on_an_allowlisted_network_is_delivered() {
    let (_tmp, state) = guarded_test_state(LOOPBACK_ALLOWLIST);
    let (base, request_rx) = spawn_http_once(http_response("text/plain", b"ok")).await;
    let mut cfg = state.cfg();
    cfg.ntfy_url = base;
    cfg.ntfy_topics = ntfy_topic();
    state.replace_config(cfg);

    assert!(post_to_ntfy(&state, "warning", &sample_parts(), 2).await);
    assert!(request_rx.await.unwrap().starts_with("POST /warning-topic"));
    assert_eq!(counter(&state, REFUSED_METRIC, &[]), 0);
}

#[tokio::test]
async fn refused_ntfy_tier_is_recorded_and_the_cascade_reaches_telegram() {
    let (_tmp, state) = guarded_test_state("127.0.0.0/8");
    let (telegram, request_rx) =
        spawn_http_once(http_response("application/json", b"{\"ok\":true}")).await;
    let mut cfg = state.cfg();
    // Private literal outside the allowlist: refused before any connection.
    cfg.ntfy_url = "http://10.255.255.1:8080".into();
    cfg.ntfy_topics = ntfy_topic();
    cfg.telegram_api_base = telegram;
    cfg.tg_token = "123:abc".into();
    cfg.tg_chat = "42".into();
    state.replace_config(cfg);

    let outcome = deliver(
        &state,
        "warning",
        sample_parts(),
        true,
        HashMap::new(),
        "grafana",
    )
    .await;

    assert_eq!(outcome, (true, "telegram".to_string()));
    assert!(
        request_rx
            .await
            .unwrap()
            .starts_with("POST /bot123:abc/sendMessage")
    );
    assert_eq!(counter(&state, REFUSED_METRIC, &["channel=ntfy"]), 1);
    let failed_ntfy = ["tier=ntfy", "ok=0"];
    assert_eq!(
        counter(&state, "klaxond_delivery_tier_attempts_total", &failed_ntfy),
        1
    );
}

#[tokio::test]
async fn refused_only_channel_is_a_failed_delivery_not_a_silent_drop() {
    let (_tmp, state) = guarded_test_state("");
    let mut cfg = state.cfg();
    cfg.ntfy_url = "http://192.168.50.100".into();
    cfg.ntfy_topics = ntfy_topic();
    state.replace_config(cfg);

    let outcome = deliver(
        &state,
        "warning",
        sample_parts(),
        false,
        HashMap::new(),
        "grafana",
    )
    .await;

    assert_eq!(outcome, (false, "ntfy-failed".to_string()));
    let failed = ["channel=ntfy-failed", "ok=0"];
    assert_eq!(counter(&state, "klaxond_deliveries_total", &failed), 1);
}

#[tokio::test]
async fn telegram_failures_never_log_the_bot_token() {
    let (_tmp, state) = guarded_test_state(LOOPBACK_ALLOWLIST);
    let mut cfg = state.cfg();
    // Discard port: nothing listens, so the send fails with a transport error.
    cfg.telegram_api_base = "http://127.0.0.1:9".into();
    cfg.tg_token = "123:very-secret-token".into();
    cfg.tg_chat = "42".into();
    state.replace_config(cfg.clone());

    assert!(!post_to_telegram(&state, "warning", &sample_parts(), 2).await);
    let url = format!("{}/bot{}/sendMessage", cfg.telegram_api_base, cfg.tg_token);
    let target = crate::outbound::Target {
        channel: "telegram",
        method: reqwest::Method::POST,
        url: &url,
    };
    let error = crate::outbound::send(&state, &cfg, target, |request| request)
        .await
        .expect_err("nothing listens on the discard port");
    assert!(!error.is_refusal());
    assert!(!error.to_string().contains("very-secret-token"), "{error}");
}

/// A DNS name that passes the static URL check but resolves to a loopback
/// address is refused by the guard's resolver at send time. That refusal must
/// be classified as a refusal (counted, logged), not as a transport error.
/// `ip6-localhost` comes from /etc/hosts (Debian and Docker map it to ::1),
/// so the test needs no network.
#[tokio::test]
async fn a_name_resolving_to_loopback_is_refused_at_resolution_and_counted() {
    if !std::fs::read_to_string("/etc/hosts").is_ok_and(|hosts| hosts.contains("ip6-localhost")) {
        eprintln!("skipped: /etc/hosts has no ip6-localhost entry");
        return;
    }
    let guard = crate::outbound::outbound_guard("").unwrap();
    let url = guard.parse_url("http://ip6-localhost:9/").unwrap();
    assert!(
        guard.check_url(&url).is_ok(),
        "the name passes the static check"
    );

    let (_tmp, state) = guarded_test_state("");
    let mut cfg = state.cfg();
    cfg.ntfy_url = "http://ip6-localhost:9".into();
    cfg.ntfy_topics = ntfy_topic();
    state.replace_config(cfg.clone());

    assert!(!post_to_ntfy(&state, "warning", &sample_parts(), 2).await);
    assert_eq!(counter(&state, REFUSED_METRIC, &["channel=ntfy"]), 1);

    let target = crate::outbound::Target {
        channel: "ntfy",
        method: reqwest::Method::POST,
        url: "http://ip6-localhost:9/warning-topic",
    };
    let error = crate::outbound::send(&state, &cfg, target, |request| request)
        .await
        .expect_err("::1 is not allowlisted");
    assert!(error.is_refusal(), "{error}");
    assert_eq!(counter(&state, REFUSED_METRIC, &["channel=ntfy"]), 2);
}
