use super::super::rate_limit::{
    clear_passkey_auth_failures, passkey_auth_store_error, record_passkey_auth_failure,
};
use crate::auth::{self, AuthRateKeys, User};
use crate::config::{PasskeyRecord, RuntimeConfig, save_auth};
use crate::handlers::{json_response, text};
use crate::state::{AppState, PendingPasskeyAuthentication};
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::Body;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use webauthn_rs::prelude::AuthenticationResult;

pub(super) fn finish_login_under_lock(
    state: &AppState,
    pending: PendingPasskeyAuthentication,
    result: AuthenticationResult,
) -> Response<Body> {
    state
        .with_config_write_lock(|| persist_login_result(state, pending, result))
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn persist_login_result(
    state: &AppState,
    pending: PendingPasskeyAuthentication,
    result: AuthenticationResult,
) -> Response<Body> {
    let mut cfg = state.cfg();
    let Some(record) = matching_credential_mut(&mut cfg.auth.passkeys, &pending, &result) else {
        return missing_credential_response(state, &pending.rate_key);
    };
    record.last_used_at = Some(crate::util::now_epoch_i64());
    let step_up = pending.step_up.clone();
    let (mut user, return_to) = match authenticated_user(state, &pending, record) {
        Ok(result) => result,
        Err(response) => return *response,
    };
    let primary_step_up = primary_step_up(state, &cfg, &user, step_up.is_none());
    if let Err(err) = save_auth(&state.paths, &cfg.auth) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
    }
    state.replace_config(cfg);
    if let Err(err) = clear_passkey_auth_failures(state, &pending.rate_key) {
        return passkey_auth_store_error("clear", err);
    }
    if let Some(location) = primary_step_up {
        return json_response(json!({"ok": true, "step_up": true, "return_to": location}));
    }
    passkey_login_response(state, &mut user, return_to.as_deref())
}

fn authenticated_user(
    state: &AppState,
    pending: &PendingPasskeyAuthentication,
    record: &PasskeyRecord,
) -> Result<(User, Option<String>), Box<Response<Body>>> {
    let Some(token) = pending.step_up.as_deref() else {
        return Ok((passkey_user(record), None));
    };
    auth::finish_webauthn_step_up(state, token, &record.user_sub)
        .map(|(user, return_to)| (user, Some(return_to)))
        .map_err(|err| {
            if let Err(store_err) =
                record_passkey_auth_failure(state, &pending.rate_key, "step-up failed")
            {
                return Box::new(passkey_auth_store_error("step-up failure", store_err));
            }
            Box::new(text(StatusCode::UNAUTHORIZED, &err))
        })
}

fn primary_step_up(
    state: &AppState,
    cfg: &RuntimeConfig,
    user: &User,
    required: bool,
) -> Option<String> {
    if required {
        auth::redirect_location_after_primary(
            state,
            &cfg.auth,
            user.clone(),
            "/status",
            PrimaryAuthMethod::Passkey,
        )
    } else {
        None
    }
}

fn missing_credential_response(state: &AppState, rate_key: &AuthRateKeys) -> Response<Body> {
    if let Err(err) = record_passkey_auth_failure(state, rate_key, "passkey credential missing") {
        return passkey_auth_store_error("credential failure", err);
    }
    text(StatusCode::UNAUTHORIZED, "passkey credential not found")
}

fn matching_credential_mut<'a>(
    records: &'a mut [PasskeyRecord],
    pending: &PendingPasskeyAuthentication,
    result: &AuthenticationResult,
) -> Option<&'a mut PasskeyRecord> {
    records.iter_mut().find_map(|record| {
        (record.user_sub == pending.user_sub
            && record.credential.update_credential(result).is_some())
        .then_some(record)
    })
}

fn passkey_user(record: &PasskeyRecord) -> User {
    User {
        sub: record.user_sub.clone(),
        email: record.user_email.clone(),
        name: record.user_name.clone(),
        groups: vec!["passkey".into()],
        mode: "passkey".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: auth::sudo_until_deadline(),
        via_authorization: false,
        second_factor: String::new(),
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: String::new(),
        provider_session_id: String::new(),
    }
}

fn passkey_login_response(
    state: &AppState,
    user: &mut User,
    return_to: Option<&str>,
) -> Response<Body> {
    let cookie = match auth::issue_session_cookie(state, user) {
        Ok(cookie) => cookie,
        Err(err) => {
            tracing::error!("persist passkey session failed: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut body = json!({"ok": true, "user": user});
    if let Some(return_to) = return_to.filter(|value| !value.is_empty()) {
        body["return_to"] = json!(return_to);
    }
    let mut response = json_response(body);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}
