use super::{rate_limited_response, rate_store_error};
use crate::auth::blocking::{authenticate_ldap, verify_password_on_worker};
use crate::auth::session::{rotate_session_on_worker, set_session_cookie};
use crate::auth::totp_replay::consume_basic_totp;
use crate::auth::{
    User, auth_rate_keys, auth_rate_limited_on_worker, clear_auth_failures_on_worker,
    json_response, login_payload, record_auth_failure_on_worker, sudo_window_seconds,
};
use crate::state::AppState;
use crate::util::now_epoch_i64;
use auth_modules::errors;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use std::net::SocketAddr;

pub async fn sudo(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
    user: Option<&User>,
) -> Response<Body> {
    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if !matches!(user.mode.as_str(), "basic" | "ldap" | "magic_link") {
        return (
            StatusCode::BAD_REQUEST,
            "sudo reauth is available only for local or LDAP login",
        )
            .into_response();
    }
    let cfg = state.cfg().auth;
    let payload = login_payload(&body);
    let password = payload.password();
    let code = payload.totp();
    let rate_keys = auth_rate_keys(state, "sudo", &user.sub, headers, Some(peer));
    match auth_rate_limited_on_worker(state, &rate_keys).await {
        Ok(true) => {
            let _ =
                record_auth_failure_on_worker(state, &rate_keys, "auth.sudo", errors::RATE_LIMITED)
                    .await;
            return rate_limited_response();
        }
        Ok(false) => {}
        Err(err) => return rate_store_error("sudo check", err),
    }
    if user.mode == "ldap" {
        if let Err(err) = authenticate_ldap(state, &cfg, &user.sub, password).await {
            tracing::warn!(?err, "LDAP sudo reauth failed");
            if let Err(store_err) =
                record_auth_failure_on_worker(state, &rate_keys, "auth.sudo", "ldap reauth failed")
                    .await
            {
                return rate_store_error("LDAP sudo failure", store_err);
            }
            return (StatusCode::UNAUTHORIZED, "invalid password").into_response();
        }
    } else if let Some(response) = verify_local_sudo(state, &cfg, &rate_keys, password, code).await
    {
        return response;
    }
    if let Err(err) = clear_auth_failures_on_worker(state, &rate_keys).await {
        return rate_store_error("sudo clear", err);
    }
    finish_sudo(state, &cfg, user).await
}

async fn verify_local_sudo(
    state: &AppState,
    cfg: &crate::config::AuthConfig,
    rate_keys: &crate::auth::AuthRateKeys,
    password: &str,
    code: &str,
) -> Option<Response<Body>> {
    if cfg.basic.password_hash.is_empty()
        || !verify_password_on_worker(state, password, &cfg.basic.password_hash).await
    {
        return record_sudo_rejection(state, rate_keys, "invalid password", "sudo failure").await;
    }
    if !cfg.basic.totp_enabled {
        return None;
    }
    match consume_basic_totp(state, code) {
        Ok(true) => None,
        Ok(false) => {
            record_sudo_rejection(
                state,
                rate_keys,
                "invalid or replayed TOTP code",
                "sudo TOTP failure",
            )
            .await
        }
        Err(err) => {
            tracing::error!("persist sudo TOTP replay counter failed: {err}");
            Some(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

async fn record_sudo_rejection(
    state: &AppState,
    rate_keys: &crate::auth::AuthRateKeys,
    detail: &'static str,
    operation: &str,
) -> Option<Response<Body>> {
    if let Err(err) = record_auth_failure_on_worker(state, rate_keys, "auth.sudo", detail).await {
        return Some(rate_store_error(operation, err));
    }
    Some((StatusCode::UNAUTHORIZED, "invalid credentials").into_response())
}

async fn finish_sudo(
    state: &AppState,
    cfg: &crate::config::AuthConfig,
    user: &User,
) -> Response<Body> {
    let mut refreshed = user.clone();
    refreshed.sudo_until = now_epoch_i64() + sudo_window_seconds();
    let cookie = match rotate_session_on_worker(state, cfg, &mut refreshed).await {
        Ok(cookie) => cookie,
        Err(err) => {
            tracing::error!("persist sudo session rotation failed: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut response = json_response(
        json!({"ok": true, "sudo_until": refreshed.sudo_until, "csrf": refreshed.csrf}),
    );
    set_session_cookie(&mut response, &cookie);
    response
}
