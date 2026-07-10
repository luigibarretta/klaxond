use super::super::{json_body, json_response, text};
use super::public::public_passkey;
use super::webauthn_config::webauthn_for_cfg;
use crate::auth::{self, User};
use crate::config::{PasskeyRecord, RuntimeConfig, save_auth};
use crate::state::{AppState, PendingPasskeyRegistration, lock_mutex};
use crate::util::random_hex;
use axum::body::{Body, Bytes};
use axum::http::HeaderValue;
use axum::http::header::SET_COOKIE;
use axum::http::{Response, StatusCode};
use serde_json::{Value, json};
use webauthn_rs::prelude::{CredentialID, Passkey, RegisterPublicKeyCredential, Uuid};

pub(in crate::handlers) fn passkey_register_start(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
) -> Response<Body> {
    let Some(user) = current_user.filter(|u| u.sub != "anonymous") else {
        return text(
            StatusCode::FORBIDDEN,
            "passkey registration requires a logged-in user",
        );
    };
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    register_start_for_user(state, user, passkey_label(&payload), None)
}

pub(in crate::handlers) fn passkey_step_up_register_start(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(token) = step_up_token(&payload) else {
        return text(StatusCode::BAD_REQUEST, "step_up token is required");
    };
    let Some(challenge) = auth::pending_step_up_challenge(state, &token) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired step-up request",
        );
    };
    if !matches!(challenge.factor.as_str(), "passkey" | "hardware_key") {
        return text(
            StatusCode::BAD_REQUEST,
            "current step-up request does not accept passkey registration",
        );
    }
    register_start_for_user(state, &challenge.user, passkey_label(&payload), Some(token))
}

fn register_start_for_user(
    state: &AppState,
    user: &User,
    label: String,
    step_up: Option<String>,
) -> Response<Body> {
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let excludes = credential_excludes(&cfg, user);
    let user_uuid = Uuid::new_v4();
    let (challenge, reg_state) = match webauthn.start_passkey_registration(
        user_uuid,
        &user.sub,
        display_name(user),
        (!excludes.is_empty()).then_some(excludes),
    ) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let request_id = random_hex(16);
    {
        let mut pending = lock_mutex(&state.passkey_registrations, "passkey registrations");
        let cutoff = crate::util::now_epoch() - 600.0;
        pending.retain(|_, v| v.ts >= cutoff);
        pending.insert(
            request_id.clone(),
            PendingPasskeyRegistration {
                ts: crate::util::now_epoch(),
                user_sub: user.sub.clone(),
                user_name: user.name.clone(),
                user_email: user.email.clone(),
                user_uuid,
                label: if label.is_empty() {
                    "passkey".into()
                } else {
                    label
                },
                step_up,
                state: reg_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

pub(in crate::handlers) fn passkey_register_finish(
    state: &AppState,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(credential_value) = payload.get("credential") else {
        return text(StatusCode::BAD_REQUEST, "missing credential");
    };
    let credential: RegisterPublicKeyCredential =
        match serde_json::from_value(credential_value.clone()) {
            Ok(v) => v,
            Err(err) => return text(StatusCode::BAD_REQUEST, &format!("bad credential: {err}")),
        };
    let Some(pending) = take_pending_registration(state, request_id) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired passkey request",
        );
    };
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let passkey = match webauthn.finish_passkey_registration(&credential, &pending.state) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            if cfg
                .auth
                .passkeys
                .iter()
                .any(|record| record.credential.cred_id() == passkey.cred_id())
            {
                return text(StatusCode::CONFLICT, "passkey already registered");
            }
            let step_up = pending.step_up.clone();
            let record = passkey_record(pending, passkey);
            cfg.auth.passkeys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            if let Some(token) = step_up {
                return passkey_step_up_response(state, &token, &record);
            }
            json_response(json!({"ok": true, "passkey": public_passkey(&record)}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn passkey_label(payload: &Value) -> String {
    payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("passkey")
        .trim()
        .chars()
        .take(80)
        .collect()
}

fn step_up_token(payload: &Value) -> Option<String> {
    payload
        .get("step_up")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn credential_excludes(cfg: &RuntimeConfig, user: &User) -> Vec<CredentialID> {
    cfg.auth
        .passkeys
        .iter()
        .filter(|passkey| passkey.user_sub == user.sub)
        .map(|passkey| passkey.credential.cred_id().clone())
        .collect()
}

fn display_name(user: &User) -> &str {
    if user.name.is_empty() {
        user.sub.as_str()
    } else {
        user.name.as_str()
    }
}

fn take_pending_registration(
    state: &AppState,
    request_id: &str,
) -> Option<PendingPasskeyRegistration> {
    let mut pending = lock_mutex(&state.passkey_registrations, "passkey registrations");
    pending.remove(request_id)
}

fn passkey_record(pending: PendingPasskeyRegistration, passkey: Passkey) -> PasskeyRecord {
    PasskeyRecord {
        id: random_hex(8),
        name: pending.label,
        user_sub: pending.user_sub,
        user_name: pending.user_name,
        user_email: pending.user_email,
        user_uuid: pending.user_uuid.to_string(),
        created_at: crate::util::now_epoch_i64(),
        last_used_at: None,
        credential: passkey,
    }
}

fn passkey_step_up_response(
    state: &AppState,
    token: &str,
    record: &PasskeyRecord,
) -> Response<Body> {
    let (mut user, return_to) = match auth::finish_webauthn_step_up(state, token, &record.user_sub)
    {
        Ok(finished) => finished,
        Err(err) => return text(StatusCode::UNAUTHORIZED, &err),
    };
    let cookie = auth::issue_session_cookie(state, &mut user);
    let mut resp = json_response(json!({
        "ok": true,
        "passkey": public_passkey(record),
        "user": user,
        "return_to": return_to,
    }));
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}
