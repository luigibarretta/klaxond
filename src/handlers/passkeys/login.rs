use super::super::{json_body, json_response, text};
use super::rate_limit::{
    clear_passkey_auth_failures, passkey_auth_rate_key, passkey_auth_rate_limited,
    passkey_auth_rate_limited_response, record_passkey_auth_failure,
};
use super::webauthn_config::webauthn_for_cfg;
use crate::auth::{self, User};
use crate::config::{PasskeyRecord, RuntimeConfig, save_auth};
use crate::state::{AppState, PendingPasskeyAuthentication, lock_mutex};
use crate::util::random_hex;
use auth_modules::step_up::PrimaryAuthMethod;
use axum::body::{Body, Bytes};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use webauthn_rs::prelude::{AuthenticationResult, Passkey, PublicKeyCredential};

struct LoginFinishPayload {
    request_id: String,
    credential: PublicKeyCredential,
}

struct PasskeyLoginIntent {
    user_sub: String,
    user_hint: String,
    step_up: Option<String>,
}

pub(in crate::handlers) fn passkey_login_start(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let intent = match passkey_login_intent(state, &payload) {
        Ok(intent) => intent,
        Err((status, message)) => return text(status, &message),
    };
    let rate_key = passkey_auth_rate_key("passkey", &intent.user_hint, headers, peer);
    if passkey_auth_rate_limited(state, &rate_key) {
        record_passkey_auth_failure(state, &rate_key, "rate_limited");
        return passkey_auth_rate_limited_response();
    }
    if intent.user_hint.is_empty() {
        record_passkey_auth_failure(state, &rate_key, "missing user");
        return text(StatusCode::BAD_REQUEST, "user is required");
    }
    let cfg = state.cfg();
    let matching = matching_passkeys(&cfg, &intent);
    if matching.is_empty() {
        record_passkey_auth_failure(state, &rate_key, "no passkey registered for user");
        return text(StatusCode::NOT_FOUND, "no passkey registered for that user");
    }
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let creds = passkey_credentials(&matching);
    let (challenge, auth_state) = match webauthn.start_passkey_authentication(&creds) {
        Ok(v) => v,
        Err(err) => {
            record_passkey_auth_failure(state, &rate_key, "passkey start failed");
            return text(StatusCode::BAD_REQUEST, &err.to_string());
        }
    };
    let request_id = random_hex(16);
    {
        let mut pending = lock_mutex(&state.passkey_authentications, "passkey authentications");
        let cutoff = crate::util::now_epoch() - 600.0;
        pending.retain(|_, v| v.ts >= cutoff);
        pending.insert(
            request_id.clone(),
            PendingPasskeyAuthentication {
                ts: crate::util::now_epoch(),
                user_sub: intent.user_sub,
                rate_key,
                step_up: intent.step_up,
                state: auth_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

pub(in crate::handlers) fn passkey_login_finish(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let unknown_rate_key = passkey_auth_rate_key("passkey", "", headers, peer);
    if passkey_auth_rate_limited(state, &unknown_rate_key) {
        record_passkey_auth_failure(state, &unknown_rate_key, "rate_limited");
        return passkey_auth_rate_limited_response();
    }
    let login = match parse_login_finish_payload(&payload) {
        Ok(login) => login,
        Err((status, message)) => return text(status, &message),
    };
    let Some(pending) = take_pending_authentication(state, &login.request_id) else {
        record_passkey_auth_failure(state, &unknown_rate_key, "unknown passkey request");
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired passkey request",
        );
    };
    if passkey_auth_rate_limited(state, &pending.rate_key) {
        record_passkey_auth_failure(state, &pending.rate_key, "rate_limited");
        return passkey_auth_rate_limited_response();
    }
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let result = match webauthn.finish_passkey_authentication(&login.credential, &pending.state) {
        Ok(v) => v,
        Err(err) => {
            record_passkey_auth_failure(state, &pending.rate_key, "passkey verification failed");
            return text(StatusCode::UNAUTHORIZED, &err.to_string());
        }
    };
    finish_login_under_lock(state, pending, result)
}

fn user_hint(payload: &Value) -> String {
    payload
        .get("user")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn passkey_login_intent(
    state: &AppState,
    payload: &Value,
) -> Result<PasskeyLoginIntent, (StatusCode, String)> {
    let step_up = payload
        .get("step_up")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(token) = step_up {
        let Some(user_sub) = auth::pending_step_up_user_sub(state, &token) else {
            return Err((
                StatusCode::BAD_REQUEST,
                "unknown or expired step-up request".into(),
            ));
        };
        return Ok(PasskeyLoginIntent {
            user_hint: user_sub.to_ascii_lowercase(),
            user_sub,
            step_up: Some(token),
        });
    }
    let user_hint = user_hint(payload);
    Ok(PasskeyLoginIntent {
        user_sub: user_hint.clone(),
        user_hint,
        step_up: None,
    })
}

fn matching_passkeys(cfg: &RuntimeConfig, intent: &PasskeyLoginIntent) -> Vec<PasskeyRecord> {
    cfg.auth
        .passkeys
        .iter()
        .filter(|record| {
            if intent.step_up.is_some() {
                return record.user_sub == intent.user_sub;
            }
            [
                record.user_sub.as_str(),
                record.user_name.as_str(),
                record.user_email.as_str(),
            ]
            .iter()
            .any(|value| value.to_ascii_lowercase() == intent.user_hint)
        })
        .cloned()
        .collect()
}

fn passkey_credentials(records: &[PasskeyRecord]) -> Vec<Passkey> {
    records
        .iter()
        .map(|record| record.credential.clone())
        .collect()
}

fn parse_login_finish_payload(payload: &Value) -> Result<LoginFinishPayload, (StatusCode, String)> {
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let Some(credential_value) = payload.get("credential") else {
        return Err((StatusCode::BAD_REQUEST, "missing credential".into()));
    };
    let credential = serde_json::from_value(credential_value.clone())
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("bad credential: {err}")))?;
    Ok(LoginFinishPayload {
        request_id,
        credential,
    })
}

fn take_pending_authentication(
    state: &AppState,
    request_id: &str,
) -> Option<PendingPasskeyAuthentication> {
    let mut pending = lock_mutex(&state.passkey_authentications, "passkey authentications");
    pending.remove(request_id)
}

fn finish_login_under_lock(
    state: &AppState,
    pending: PendingPasskeyAuthentication,
    result: AuthenticationResult,
) -> Response<Body> {
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let Some(record) = matching_credential_mut(&mut cfg.auth.passkeys, &pending, &result)
            else {
                record_passkey_auth_failure(state, &pending.rate_key, "passkey credential missing");
                return text(StatusCode::UNAUTHORIZED, "passkey credential not found");
            };
            record.last_used_at = Some(crate::util::now_epoch_i64());
            let step_up = pending.step_up.clone();
            let (mut user, return_to) = match step_up.as_deref() {
                Some(token) => {
                    match auth::finish_webauthn_step_up(state, token, &record.user_sub) {
                        Ok((user, return_to)) => (user, Some(return_to)),
                        Err(err) => {
                            record_passkey_auth_failure(state, &pending.rate_key, "step-up failed");
                            return text(StatusCode::UNAUTHORIZED, &err);
                        }
                    }
                }
                None => (passkey_user(record), None),
            };
            let primary_step_up = if step_up.is_none() {
                auth::redirect_location_after_primary(
                    state,
                    &cfg.auth,
                    user.clone(),
                    "/status",
                    PrimaryAuthMethod::Passkey,
                )
            } else {
                None
            };
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            clear_passkey_auth_failures(state, &pending.rate_key);
            if let Some(location) = primary_step_up {
                return json_response(json!({"ok": true, "step_up": true, "return_to": location}));
            }
            passkey_login_response(state, &mut user, return_to.as_deref())
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
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
    }
}

fn passkey_login_response(
    state: &AppState,
    user: &mut User,
    return_to: Option<&str>,
) -> Response<Body> {
    let cookie = auth::issue_session_cookie(state, user);
    let mut body = json!({"ok": true, "user": user});
    if let Some(return_to) = return_to.filter(|value| !value.is_empty()) {
        body["return_to"] = json!(return_to);
    }
    let mut resp = json_response(body);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}
