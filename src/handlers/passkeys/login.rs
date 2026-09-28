use super::super::{json_body, json_response, text};
use super::rate_limit::{
    passkey_auth_rate_key, passkey_auth_rate_limited, passkey_auth_rate_limited_response,
    passkey_auth_store_error, record_passkey_auth_failure,
};
use super::webauthn_config::webauthn_for_cfg;
use crate::auth::{self, AuthRateKeys};
use crate::config::{PasskeyRecord, RuntimeConfig};
use crate::state::{AppState, PendingPasskeyAuthentication, lock_mutex};
use crate::util::random_hex;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential};

mod finish;

use self::finish::finish_login_under_lock;

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
    let rate_key = passkey_auth_rate_key(state, "passkey", &intent.user_hint, headers, peer);
    match passkey_auth_rate_limited(state, &rate_key) {
        Ok(true) => {
            let _ = record_passkey_auth_failure(state, &rate_key, "rate_limited");
            return passkey_auth_rate_limited_response();
        }
        Ok(false) => {}
        Err(err) => return passkey_auth_store_error("check", err),
    }
    if intent.user_hint.is_empty() {
        if let Err(err) = record_passkey_auth_failure(state, &rate_key, "missing user") {
            return passkey_auth_store_error("missing-user failure", err);
        }
        return text(StatusCode::BAD_REQUEST, "user is required");
    }
    let cfg = state.cfg();
    let matching = matching_passkeys(&cfg, &intent);
    if matching.is_empty() {
        if let Err(err) =
            record_passkey_auth_failure(state, &rate_key, "no passkey registered for user")
        {
            return passkey_auth_store_error("unknown-user failure", err);
        }
        return text(StatusCode::NOT_FOUND, "no passkey registered for that user");
    }
    start_passkey_challenge(state, &cfg, intent, matching, rate_key)
}

fn start_passkey_challenge(
    state: &AppState,
    cfg: &RuntimeConfig,
    intent: PasskeyLoginIntent,
    matching: Vec<PasskeyRecord>,
    rate_key: AuthRateKeys,
) -> Response<Body> {
    let webauthn = match webauthn_for_cfg(cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let creds = passkey_credentials(&matching);
    let (challenge, auth_state) = match webauthn.start_passkey_authentication(&creds) {
        Ok(v) => v,
        Err(err) => {
            if let Err(store_err) =
                record_passkey_auth_failure(state, &rate_key, "passkey start failed")
            {
                return passkey_auth_store_error("start failure", store_err);
            }
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
    let unknown_rate_key = passkey_auth_rate_key(state, "passkey", "", headers, peer);
    match passkey_auth_rate_limited(state, &unknown_rate_key) {
        Ok(true) => {
            let _ = record_passkey_auth_failure(state, &unknown_rate_key, "rate_limited");
            return passkey_auth_rate_limited_response();
        }
        Ok(false) => {}
        Err(err) => return passkey_auth_store_error("unknown-request check", err),
    }
    let login = match parse_login_finish_payload(&payload) {
        Ok(login) => login,
        Err((status, message)) => return text(status, &message),
    };
    let Some(pending) = take_pending_authentication(state, &login.request_id) else {
        if let Err(err) =
            record_passkey_auth_failure(state, &unknown_rate_key, "unknown passkey request")
        {
            return passkey_auth_store_error("unknown-request failure", err);
        }
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired passkey request",
        );
    };
    match passkey_auth_rate_limited(state, &pending.rate_key) {
        Ok(true) => {
            let _ = record_passkey_auth_failure(state, &pending.rate_key, "rate_limited");
            return passkey_auth_rate_limited_response();
        }
        Ok(false) => {}
        Err(err) => return passkey_auth_store_error("verification check", err),
    }
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let result = match webauthn.finish_passkey_authentication(&login.credential, &pending.state) {
        Ok(v) => v,
        Err(err) => {
            if let Err(store_err) =
                record_passkey_auth_failure(state, &pending.rate_key, "passkey verification failed")
            {
                return passkey_auth_store_error("verification failure", store_err);
            }
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
