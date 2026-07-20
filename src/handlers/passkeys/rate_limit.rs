use super::super::text;
use crate::auth::{
    AuthRateKeys, auth_rate_keys, auth_rate_limited, clear_auth_failures, record_auth_failure,
};
use crate::state::AppState;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use std::net::SocketAddr;

pub(super) fn passkey_auth_rate_key(
    state: &AppState,
    action: &str,
    subject: &str,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> AuthRateKeys {
    auth_rate_keys(state, action, subject, headers, Some(peer))
}

pub(super) fn passkey_auth_rate_limited(
    state: &AppState,
    rate_key: &AuthRateKeys,
) -> Result<bool, String> {
    auth_rate_limited(state, rate_key)
}

pub(super) fn record_passkey_auth_failure(
    state: &AppState,
    rate_key: &AuthRateKeys,
    detail: &'static str,
) -> Result<(), String> {
    let canonical = if detail == "rate_limited" {
        auth_modules::errors::RATE_LIMITED
    } else {
        detail
    };
    record_auth_failure(state, rate_key, "auth.passkey", canonical)
}

pub(super) fn clear_passkey_auth_failures(
    state: &AppState,
    rate_key: &AuthRateKeys,
) -> Result<(), String> {
    clear_auth_failures(state, rate_key)
}

pub(super) fn passkey_auth_rate_limited_response() -> Response<Body> {
    text(
        StatusCode::TOO_MANY_REQUESTS,
        "too many authentication failures",
    )
}

pub(super) fn passkey_auth_store_error(operation: &str, err: String) -> Response<Body> {
    tracing::error!("persistent passkey rate-limit {operation} failed: {err}");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}
