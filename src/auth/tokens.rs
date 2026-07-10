use super::{AuthOutcome, User};
use crate::config::{AuthToken, save_auth};
use crate::endpoints;
use crate::state::AppState;
use crate::util::now_epoch_i64;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use constant_time_eq::constant_time_eq;
use serde_json::Value;
use sha2::{Digest, Sha256};

const TOKEN_LAST_USED_PERSIST_INTERVAL_SECS: i64 = 60;

pub(super) fn authenticate_api_token(
    state: &AppState,
    token: &str,
    method: &Method,
    path: &str,
) -> AuthOutcome {
    let cfg = state.cfg().auth;
    let hash = token_hash(token);
    let now = now_epoch_i64();
    let Some(record) = valid_token_record(&cfg.api_keys, &hash, now) else {
        return AuthOutcome::Rejected(
            (StatusCode::UNAUTHORIZED, "invalid bearer token").into_response(),
        );
    };
    let required = required_scope(method, path);
    if !has_scope(&record.scopes, required) {
        return AuthOutcome::Rejected(
            (
                StatusCode::FORBIDDEN,
                format!("token missing required scope '{required}'"),
            )
                .into_response(),
        );
    }
    let record = record.clone();
    persist_token_last_used(state, &record, &hash, now);

    AuthOutcome::Authorized(token_user(record), None)
}

fn valid_token_record<'a>(records: &'a [AuthToken], hash: &str, now: i64) -> Option<&'a AuthToken> {
    records.iter().find(|record| {
        record.enabled
            && !token_is_expired(record, now)
            && constant_time_eq(record.token_hash.as_bytes(), hash.as_bytes())
    })
}

fn token_is_expired(record: &AuthToken, now: i64) -> bool {
    record
        .expires_at
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
}

fn last_used_update_due(record: &AuthToken, now: i64) -> bool {
    record
        .last_used_at
        .map(|last| now.saturating_sub(last) >= TOKEN_LAST_USED_PERSIST_INTERVAL_SECS)
        .unwrap_or(true)
}

fn persist_token_last_used(state: &AppState, record: &AuthToken, hash: &str, now: i64) {
    if !last_used_update_due(record, now) {
        return;
    }

    let record_id = record.id.clone();
    if let Err(err) = state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        if let Some(stored) = cfg
            .auth
            .api_keys
            .iter_mut()
            .find(|stored| stored.id == record_id && stored.token_hash == hash)
        {
            if !last_used_update_due(stored, now) {
                return;
            }
            stored.last_used_at = Some(now);
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                tracing::warn!("failed to persist auth token last_used_at: {err}");
                return;
            }
            state.replace_config_preserving_runtime(cfg);
        }
    }) {
        tracing::warn!("failed to update auth token last_used_at: {err}");
    }
}

fn token_user(record: AuthToken) -> User {
    User {
        sub: format!("token:{}", record.name),
        email: String::new(),
        name: record.name,
        groups: record.scopes,
        mode: record.kind,
        exp: record.expires_at.unwrap_or(0),
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: true,
        second_factor: String::new(),
    }
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn public_token(record: &AuthToken) -> Value {
    serde_json::json!({
        "id": record.id,
        "name": record.name,
        "kind": record.kind,
        "prefix": record.prefix,
        "scopes": record.scopes,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "last_used_at": record.last_used_at,
        "enabled": record.enabled,
    })
}

pub fn required_scope(method: &Method, path: &str) -> &'static str {
    endpoints::required_scope(method, path)
}

fn has_scope(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| {
        let scope = scope.as_str();
        scope == "admin:*"
            || scope == required
            || (scope == "admin:read" && required.ends_with(":read"))
            || (scope == "viewer:*" && viewer_allows_scope(required))
            || scope
                .strip_suffix(":*")
                .zip(required.split_once(':'))
                .map(|(prefix, (group, _))| prefix == group)
                .unwrap_or(false)
    })
}

pub fn scopes_allow(scopes: &[String], required: &str) -> bool {
    has_scope(scopes, required)
}

pub(super) fn viewer_allows_scope(required: &str) -> bool {
    matches!(required, "status:read" | "logs:read" | "audit:read")
}
