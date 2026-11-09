//! Negative tests for K-01: magic links are delivered only out of band.

use super::hash_password;
use super::magic_link::{
    MagicLinkError, consume_magic_link, issue_magic_link, magic_link_callback,
    magic_link_email_body, magic_link_enabled, magic_link_request,
};
use super::test_support::{delivered, temp_paths};
use crate::config::{RuntimeConfig, TotpRecord};
use crate::delivery::channels::smtp_ready;
use crate::state::{AppState, lock_mutex};
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use std::net::SocketAddr;
use tempfile::TempDir;

const CALLBACK_PATH: &str = "/api/auth/magic/callback/";

fn enabled_runtime(state: &AppState) -> RuntimeConfig {
    let mut runtime = state.cfg();
    runtime.public_url = "https://klaxond.example.test".to_string();
    runtime.auth.mode = "basic".to_string();
    runtime.auth.magic_link_enabled = true;
    runtime.auth.basic.username = "luigi".to_string();
    runtime.auth.basic.password_hash = hash_password("correct horse battery staple").unwrap();
    runtime.auth.basic.totp_enabled = false;
    // Loopback port 1: background delivery fails fast with no DNS or egress.
    runtime.smtp_host = "127.0.0.1".to_string();
    runtime.smtp_port = 1;
    runtime.smtp_starttls = true;
    runtime.smtp_user = "klaxond".to_string();
    runtime.smtp_pass = "smtp-password".to_string();
    runtime.smtp_from = "klaxond@example.test".to_string();
    runtime.smtp_to = "operator@example.test".to_string();
    runtime
}

fn new_state(tmp: &TempDir) -> AppState {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    AppState::new(temp_paths(tmp)).unwrap()
}

fn peer() -> SocketAddr {
    "198.51.100.7:40000".parse().unwrap()
}

async fn body_text(resp: Response<Body>) -> String {
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn location(resp: &Response<Body>) -> String {
    resp.headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn pending_count(state: &AppState) -> usize {
    lock_mutex(&state.magic_links, "magic links").len()
}

#[test]
fn magic_link_is_fail_closed_without_opt_in_smtp_or_with_totp() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    let base = enabled_runtime(&state);
    assert!(magic_link_enabled(&base));

    let mut cfg = base.clone();
    cfg.auth.magic_link_enabled = false;
    assert!(!magic_link_enabled(&cfg), "explicit opt-in is required");

    let mut cfg = base.clone();
    cfg.smtp_host.clear();
    assert!(!magic_link_enabled(&cfg), "an SMTP channel is required");

    let mut cfg = base.clone();
    cfg.smtp_from.clear();
    assert!(!magic_link_enabled(&cfg), "a sender address is required");

    let mut cfg = base.clone();
    cfg.smtp_starttls = false;
    assert!(
        !magic_link_enabled(&cfg),
        "the link must never be mailed over clear-text SMTP"
    );
    assert!(
        smtp_ready(&cfg),
        "ordinary SMTP alerts still accept smtp_starttls = false"
    );

    let mut cfg = base.clone();
    cfg.public_url.clear();
    assert!(
        !magic_link_enabled(&cfg),
        "an absolute public URL is required"
    );

    let mut cfg = base.clone();
    cfg.auth.basic.totp_enabled = true;
    assert!(
        !magic_link_enabled(&cfg),
        "magic link must not skip basic TOTP"
    );

    let mut cfg = base.clone();
    cfg.auth.basic.totp_secret = "JBSWY3DPEHPK3PXP".to_string();
    assert!(
        !magic_link_enabled(&cfg),
        "a stored basic TOTP secret also disables magic links"
    );

    let mut cfg = base.clone();
    cfg.auth.totp_factors.push(TotpRecord {
        id: "t1".to_string(),
        name: "phone".to_string(),
        user_sub: "luigi".to_string(),
        user_name: String::new(),
        user_email: String::new(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        created_at: 0,
        last_used_at: None,
        last_used_counter: None,
    });
    assert!(
        !magic_link_enabled(&cfg),
        "magic link must not skip a TOTP factor"
    );
}

#[tokio::test]
async fn magic_link_request_never_returns_the_token_or_an_existence_oracle() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    state.replace_config(enabled_runtime(&state));
    let headers = HeaderMap::new();

    let known = magic_link_request(
        &state,
        &headers,
        peer(),
        Bytes::from_static(br#"{"username":"luigi","return_to":"/status"}"#),
    );
    assert_eq!(known.status(), StatusCode::ACCEPTED);
    assert!(location(&known).is_empty());
    let known_body = body_text(known).await;
    assert_eq!(pending_count(&state), 1, "token issued for the known user");

    let unknown = magic_link_request(
        &state,
        &headers,
        peer(),
        Bytes::from_static(br#"{"username":"nobody","return_to":"/status"}"#),
    );
    assert_eq!(unknown.status(), StatusCode::ACCEPTED);
    let unknown_body = body_text(unknown).await;
    assert_eq!(pending_count(&state), 1, "no token for unknown users");

    assert_eq!(
        known_body, unknown_body,
        "response must not reveal the user"
    );
    let value: serde_json::Value = serde_json::from_str(&known_body).unwrap();
    assert_eq!(value["sent"], true);
    assert!(value.get("link").is_none());
    assert!(!known_body.contains(CALLBACK_PATH));
    assert!(!known_body.contains("klaxond.example.test"));
}

#[tokio::test]
async fn magic_link_form_request_never_redirects_to_the_callback() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    state.replace_config(enabled_runtime(&state));
    let headers = HeaderMap::new();

    let known = magic_link_request(
        &state,
        &headers,
        peer(),
        Bytes::from_static(b"username=luigi&return_to=%2Fstatus"),
    );
    let unknown = magic_link_request(
        &state,
        &headers,
        peer(),
        Bytes::from_static(b"username=nobody&return_to=%2Fstatus"),
    );
    assert_eq!(known.status(), StatusCode::FOUND);
    assert_eq!(unknown.status(), StatusCode::FOUND);
    assert_eq!(location(&known), location(&unknown));
    assert!(location(&known).starts_with("/api/auth/login?magic_sent=1"));
    assert!(!location(&known).contains(CALLBACK_PATH));
    assert!(!body_text(known).await.contains(CALLBACK_PATH));
}

#[tokio::test]
async fn magic_link_endpoints_are_unavailable_when_not_configured() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    // Basic auth without opt-in/SMTP: the pre-K-01 default that leaked links.
    let mut runtime = enabled_runtime(&state);
    runtime.auth.magic_link_enabled = false;
    state.replace_config(runtime);

    let resp = magic_link_request(
        &state,
        &HeaderMap::new(),
        peer(),
        Bytes::from_static(br#"{"username":"luigi"}"#),
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(pending_count(&state), 0);
    assert_eq!(
        magic_link_callback(&state, "anything").await.status(),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn new_magic_link_revokes_the_previous_unused_link() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    let runtime = enabled_runtime(&state);
    state.replace_config(runtime.clone());

    let first = delivered(issue_magic_link(&state, &runtime.auth, "luigi", "/status").unwrap());
    let second = delivered(issue_magic_link(&state, &runtime.auth, "luigi", "/status").unwrap());
    assert_eq!(pending_count(&state), 1, "only one valid link per user");
    assert!(matches!(
        consume_magic_link(&state, &runtime.auth, &first),
        Err(MagicLinkError::Invalid)
    ));
    assert!(consume_magic_link(&state, &runtime.auth, &second).is_ok());
}

#[tokio::test]
async fn global_issue_cap_keeps_the_uniform_answer_and_sends_nothing() {
    let tmp = TempDir::new().unwrap();
    let state = new_state(&tmp);
    let runtime = enabled_runtime(&state);
    state.replace_config(runtime.clone());

    // Burn the global budget (5 issuances per 15 minutes).
    let mut last = String::new();
    for _ in 0..5 {
        last = delivered(issue_magic_link(&state, &runtime.auth, "luigi", "/status").unwrap());
    }
    assert!(
        issue_magic_link(&state, &runtime.auth, "luigi", "/status").is_none(),
        "no token beyond the global cap"
    );

    let capped = magic_link_request(
        &state,
        &HeaderMap::new(),
        peer(),
        Bytes::from_static(br#"{"username":"luigi","return_to":"/status"}"#),
    );
    assert_eq!(capped.status(), StatusCode::ACCEPTED);
    let capped_body = body_text(capped).await;
    let unknown = magic_link_request(
        &state,
        &HeaderMap::new(),
        peer(),
        Bytes::from_static(br#"{"username":"nobody","return_to":"/status"}"#),
    );
    assert_eq!(capped_body, body_text(unknown).await);

    // The capped request neither issued a token nor revoked the pending one.
    assert_eq!(pending_count(&state), 1);
    assert!(consume_magic_link(&state, &runtime.auth, &last).is_ok());
}

#[test]
fn magic_link_email_names_the_requester_ip_and_time() {
    let body = magic_link_email_body(
        "https://klaxond.example.test/api/auth/magic/callback/tok",
        "198.51.100.7",
        "2026-11-07T10:00:00Z",
    );
    assert!(body.contains("Requested from: 198.51.100.7"));
    assert!(body.contains("Requested at: 2026-11-07T10:00:00Z"));
    assert!(body.contains("/api/auth/magic/callback/tok"));
}
