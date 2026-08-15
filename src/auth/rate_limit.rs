use super::blocking::{AUTH_STORE_TIMEOUT, run_with_timeout};
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::audit::AuthAuditKind;
use auth_modules::errors;
use auth_modules::rate_limit::{GOLD_AUTH_IP_BURST_MAX, GOLD_AUTH_IP_BURST_WINDOW};
use axum::http::HeaderMap;
use serde_json::json;
use std::net::SocketAddr;

mod client_ip;

pub(in crate::auth) use client_ip::client_ip;

#[derive(Clone, Debug)]
pub(crate) struct AuthRateKeys {
    account: String,
    ip: String,
}

pub(crate) fn auth_rate_keys(
    state: &AppState,
    action: &str,
    subject: &str,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> AuthRateKeys {
    let subject = subject.trim().to_ascii_lowercase();
    let subject = if subject.is_empty() {
        "unknown"
    } else {
        subject.as_str()
    };
    AuthRateKeys {
        account: format!("{action}:account:{subject}"),
        ip: format!("{action}:ip:{}", client_ip(state, headers, peer)),
    }
}

pub(crate) fn auth_rate_limited(state: &AppState, keys: &AuthRateKeys) -> Result<bool, String> {
    let account_limited = state
        .with_auth_store(|store| {
            store.auth_rate_limited(&account_key_hash(state, &keys.account), now_epoch_i64())
        })
        .map_err(|err| err.to_string())?;
    let ip_limited =
        state
            .auth_failures
            .blocked(&keys.ip, GOLD_AUTH_IP_BURST_MAX, GOLD_AUTH_IP_BURST_WINDOW);
    Ok(account_limited || ip_limited)
}

pub(crate) fn record_auth_failure(
    state: &AppState,
    keys: &AuthRateKeys,
    action: &'static str,
    detail: &'static str,
) -> Result<(), String> {
    if detail != errors::RATE_LIMITED {
        state
            .with_auth_store(|store| {
                store.record_auth_failure(&account_key_hash(state, &keys.account), now_epoch_i64())
            })
            .map_err(|err| err.to_string())?;
        state
            .auth_failures
            .record(&keys.ip, GOLD_AUTH_IP_BURST_WINDOW);
    }
    let kind = auth_audit_kind_for_failure(action, detail);
    record_auth_audit_failure(keys.account.clone(), action, kind, detail);
    Ok(())
}

pub(crate) fn clear_auth_failures(state: &AppState, keys: &AuthRateKeys) -> Result<(), String> {
    state
        .with_auth_store(|store| store.clear_auth_failures(&account_key_hash(state, &keys.account)))
        .map_err(|err| err.to_string())
}

pub(crate) async fn auth_rate_limited_on_worker(
    state: &AppState,
    keys: &AuthRateKeys,
) -> Result<bool, String> {
    let state_for_store = state.clone();
    let keys = keys.clone();
    run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        auth_rate_limited(&state_for_store, &keys)
    })
    .await?
}

pub(crate) async fn record_auth_failure_on_worker(
    state: &AppState,
    keys: &AuthRateKeys,
    action: &'static str,
    detail: &'static str,
) -> Result<(), String> {
    let state_for_store = state.clone();
    let keys = keys.clone();
    run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        record_auth_failure(&state_for_store, &keys, action, detail)
    })
    .await?
}

pub(crate) async fn clear_auth_failures_on_worker(
    state: &AppState,
    keys: &AuthRateKeys,
) -> Result<(), String> {
    let state_for_store = state.clone();
    let keys = keys.clone();
    run_with_timeout(state, AUTH_STORE_TIMEOUT, move || {
        clear_auth_failures(&state_for_store, &keys)
    })
    .await?
}

fn auth_audit_kind_for_failure(action: &str, detail: &str) -> AuthAuditKind {
    if detail == errors::RATE_LIMITED {
        AuthAuditKind::RateLimitExceeded
    } else if action == "auth.ldap" {
        AuthAuditKind::LdapLoginFailure
    } else if detail.contains("TOTP") {
        AuthAuditKind::TotpVerificationFailure
    } else {
        AuthAuditKind::LoginFailure
    }
}

pub(super) fn record_auth_audit_failure(
    actor: String,
    action: &str,
    kind: AuthAuditKind,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    crate::audit::record(
        actor,
        action,
        "error",
        json!({
            "kind": kind.as_str(),
            "reason": detail,
        })
        .to_string(),
    );
}

fn account_key_hash(state: &AppState, account_key: &str) -> String {
    crate::util::hmac_hex(
        state.session_key.as_slice(),
        format!("klaxond-auth-rate-v1\0{account_key}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
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
}
