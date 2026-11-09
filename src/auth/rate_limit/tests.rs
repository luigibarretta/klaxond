use super::*;
use crate::auth::test_support::temp_paths;
use axum::http::HeaderValue;
use std::net::{IpAddr, Ipv4Addr};
use tempfile::TempDir;

#[test]
fn rate_keys_separate_account_and_ip_dimensions() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.7, 192.0.2.2"),
    );
    let keys = auth_rate_keys(
        &state,
        "login",
        " Alice ",
        &headers,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)),
    );
    assert_eq!(keys.account, "login:account:alice");
    assert_eq!(keys.ip, "login:ip:192.0.2.2");

    let untrusted = auth_rate_keys(
        &state,
        "login",
        "Alice",
        &headers,
        Some("198.51.100.9:1234".parse().unwrap()),
    );
    assert_eq!(untrusted.ip, "login:ip:198.51.100.9");
}

#[test]
fn forwarded_chain_stops_at_first_untrusted_hop() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.66, 203.0.113.7"),
    );
    let keys = auth_rate_keys(
        &state,
        "login",
        "alice",
        &headers,
        Some("127.0.0.1:1234".parse().unwrap()),
    );

    assert_eq!(keys.ip, "login:ip:203.0.113.7");
}

#[test]
fn duplicate_forwarded_headers_are_processed_in_wire_order() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.66"));
    headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));

    let keys = auth_rate_keys(
        &state,
        "login",
        "alice",
        &headers,
        Some("127.0.0.1:1234".parse().unwrap()),
    );

    assert_eq!(keys.ip, "login:ip:203.0.113.7");
}

#[test]
fn private_network_peer_is_not_a_trusted_proxy_by_default() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.66"));

    let keys = auth_rate_keys(
        &state,
        "login",
        "alice",
        &headers,
        Some("192.168.50.42:1234".parse().unwrap()),
    );

    assert_eq!(keys.ip, "login:ip:192.168.50.42");
}

#[test]
fn persistent_store_hashes_account_keys() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
    let keys = auth_rate_keys(&state, "login", "alice@example.test", &headers, None);
    record_auth_failure(&state, &keys, "auth.login", "invalid password").unwrap();

    let conn = rusqlite::Connection::open(&state.paths.history_db).unwrap();
    let stored: String = conn
        .query_row("SELECT key_hash FROM klaxond_auth_rate_limits", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_ne!(stored, keys.account);
    assert!(!stored.contains("alice"));
    assert!(!stored.contains("203.0.113.7"));
}

#[test]
fn lockouts_recorded_with_the_raw_secret_still_apply_and_clear() {
    let tmp = TempDir::new().unwrap();
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
        AppState::new(temp_paths(&tmp)).unwrap()
    };
    let keys = auth_rate_keys(&state, "login", "alice", &HeaderMap::new(), None);
    let legacy = legacy_account_key_hash(&state, &keys.account);
    assert_ne!(legacy, account_key_hash(&state, &keys.account));
    let now = now_epoch_i64();
    state.with_auth_store(|store| {
        for _ in 0..auth_modules::rate_limit::GOLD_AUTH_ACCOUNT_FAILURE_MAX {
            store.record_auth_failure(&legacy, now).unwrap();
        }
    });
    assert!(auth_rate_limited(&state, &keys).unwrap());
    clear_auth_failures(&state, &keys).unwrap();
    assert!(!auth_rate_limited(&state, &keys).unwrap());
}
