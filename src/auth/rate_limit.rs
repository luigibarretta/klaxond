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

pub(crate) use client_ip::client_ip;

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
    let now = now_epoch_i64();
    let account_limited = state
        .with_auth_store(|store| {
            // A lockout recorded before 0.23 is keyed by the raw-secret hash.
            Ok::<_, anyhow::Error>(
                store.auth_rate_limited(&account_key_hash(state, &keys.account), now)?
                    || store
                        .auth_rate_limited(&legacy_account_key_hash(state, &keys.account), now)?,
            )
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
        .with_auth_store(|store| {
            store.clear_auth_failures(&account_key_hash(state, &keys.account))?;
            store.clear_auth_failures(&legacy_account_key_hash(state, &keys.account))
        })
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

fn account_key_input(account_key: &str) -> String {
    format!("klaxond-auth-rate-v1\0{account_key}")
}

fn account_key_hash(state: &AppState, account_key: &str) -> String {
    state.keys.sign_hex(
        crate::state::keys::AUTH_RATE_ACCOUNT,
        account_key_input(account_key).as_bytes(),
    )
}

/// The pre-0.23 raw-secret key of the same account; checked and cleared until
/// the lockout windows recorded before the upgrade have passed.
fn legacy_account_key_hash(state: &AppState, account_key: &str) -> String {
    state
        .keys
        .legacy_hex(account_key_input(account_key).as_bytes())
}

#[cfg(test)]
mod tests;
