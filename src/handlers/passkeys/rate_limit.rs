use super::super::text;
use crate::audit;
use crate::state::AppState;
use auth_modules::rate_limit::{GOLD_AUTH_ACCOUNT_FAILURE_MAX, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW};
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use std::net::SocketAddr;

pub(super) fn passkey_auth_rate_key(
    action: &str,
    subject: &str,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> String {
    let subject = subject.trim().to_ascii_lowercase();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
        .unwrap_or_else(|| peer.ip().to_string());
    format!(
        "{action}:{}:{ip}",
        if subject.is_empty() {
            "unknown"
        } else {
            subject.as_str()
        }
    )
}

pub(super) fn passkey_auth_rate_limited(state: &AppState, rate_key: &str) -> bool {
    state.auth_failures.blocked(
        rate_key,
        GOLD_AUTH_ACCOUNT_FAILURE_MAX,
        GOLD_AUTH_ACCOUNT_FAILURE_WINDOW,
    )
}

pub(super) fn record_passkey_auth_failure(state: &AppState, rate_key: &str, detail: &'static str) {
    state
        .auth_failures
        .record(rate_key, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW);
    audit::record(
        rate_key.to_string(),
        "auth.passkey",
        "error",
        detail.to_string(),
    );
}

pub(super) fn clear_passkey_auth_failures(state: &AppState, rate_key: &str) {
    state.auth_failures.clear(rate_key);
}

pub(super) fn passkey_auth_rate_limited_response() -> Response<Body> {
    text(
        StatusCode::TOO_MANY_REQUESTS,
        "too many authentication failures",
    )
}
