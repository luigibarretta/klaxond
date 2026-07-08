use super::{json_response, login_payload};
use crate::config::save_auth;
use crate::state::AppState;
use crate::totp;
use crate::util::now_epoch_i64;
use axum::body::{Body, Bytes};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

pub fn totp_start(state: &AppState) -> Response<Body> {
    let cfg = state.cfg().auth;
    let secret = totp::generate_secret();
    let label = if cfg.basic.username.trim().is_empty() {
        "klaxond".to_string()
    } else {
        format!("klaxond:{}", cfg.basic.username)
    };
    let otpauth_uri = totp::otpauth_uri(&label, "klaxond", &secret);
    json_response(json!({"ok": true, "secret": secret, "otpauth_uri": otpauth_uri}))
}

pub fn totp_enable(state: &AppState, body: Bytes) -> Response<Body> {
    let payload = login_payload(&body);
    let secret = payload
        .get("secret")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    let code = payload.get("code").map(String::as_str).unwrap_or("").trim();
    if !totp::is_valid_secret(&secret) {
        return (StatusCode::BAD_REQUEST, "invalid TOTP secret").into_response();
    }
    if !totp::verify_code(&secret, code, now_epoch_i64()) {
        return (StatusCode::BAD_REQUEST, "invalid TOTP code").into_response();
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.basic.totp_enabled = true;
            cfg.auth.basic.totp_secret = secret.clone();
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "enabled": true}))
        })
        .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err).into_response())
}

pub fn totp_disable(state: &AppState) -> Response<Body> {
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.basic.totp_enabled = false;
            cfg.auth.basic.totp_secret.clear();
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "enabled": false}))
        })
        .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err).into_response())
}
