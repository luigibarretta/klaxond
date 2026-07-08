use super::super::{json_body, json_response, text};
use crate::auth::{self, User};
use crate::config::{AuthToken, save_auth};
use crate::state::AppState;
use crate::util::{random_hex, token_urlsafe};
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use serde_json::json;

pub(in crate::handlers) fn create_auth_token(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token name is required");
    }
    let kind = payload
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("api-key")
        .trim();
    if !matches!(kind, "api-key" | "pat") {
        return text(StatusCode::BAD_REQUEST, "kind must be api-key or pat");
    }
    let scopes = payload
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if scopes.is_empty() {
        return text(StatusCode::BAD_REQUEST, "at least one scope is required");
    }
    for scope in &scopes {
        if !auth::TOKEN_SCOPES.contains(&scope.as_str()) {
            return text(StatusCode::BAD_REQUEST, &format!("invalid scope '{scope}'"));
        }
    }
    if !token_scopes_allowed_for_actor(current_user, &scopes) {
        return text(
            StatusCode::FORBIDDEN,
            "requested token scopes exceed the authenticated token scope",
        );
    }
    let now = crate::util::now_epoch_i64();
    let expires_at = payload
        .get("expires_in_days")
        .and_then(|v| v.as_u64())
        .filter(|days| *days > 0)
        .map(|days| now + (days.min(3650) * 86_400) as i64)
        .or_else(|| {
            payload
                .get("expires_at")
                .and_then(|v| v.as_i64())
                .filter(|v| *v > now)
        });
    let token = format!(
        "klx_{}_{}",
        if kind == "pat" { "pat" } else { "key" },
        token_urlsafe(32)
    );
    let record = AuthToken {
        id: random_hex(8),
        name: name.to_string(),
        kind: kind.to_string(),
        prefix: token.chars().take(18).collect(),
        token_hash: auth::token_hash(&token),
        scopes,
        created_at: now,
        expires_at,
        last_used_at: None,
        enabled: true,
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.api_keys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({
                "ok": true,
                "token": token,
                "record": auth::public_token(&record),
            }))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn token_scopes_allowed_for_actor(current_user: Option<&User>, requested: &[String]) -> bool {
    let Some(user) = current_user else {
        return true;
    };
    if !user.via_authorization {
        return true;
    }
    requested
        .iter()
        .all(|scope| auth::scopes_allow(&user.groups, scope))
}

pub(in crate::handlers) fn revoke_auth_token(state: &AppState, id: &str) -> Response<Body> {
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut changed = false;
            for token in &mut cfg.auth.api_keys {
                if token.id == id {
                    token.enabled = false;
                    changed = true;
                }
            }
            if !changed {
                return text(StatusCode::NOT_FOUND, "token not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(in crate::handlers) fn password_policy_response() -> Response<Body> {
    let profile = auth_modules::security_profile::GoldAuthProfile::personal_default();
    let policy = profile.password_policy;
    json_response(json!({
        "min_length": policy.min_length,
        "max_length": policy.max_length,
    }))
}
