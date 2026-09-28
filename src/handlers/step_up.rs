use super::{json_body, json_response, text};
use crate::auth::{self, StepUpChallenge};
use crate::config::{TotpRecord, save_auth};
use crate::state::{AppState, PendingTotpRegistration, lock_mutex};
use crate::totp;
use crate::util::{now_epoch_i64, random_hex};
use axum::body::{Body, Bytes};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, Response, StatusCode};
use serde_json::{Value, json};
use url::Url;

mod page;

pub(super) use page::step_up_page;

#[cfg(test)]
mod tests;

const STEP_UP_TOTP_TTL_SECONDS: f64 = 600.0;

pub(super) fn step_up_status_response(state: &AppState, full_path: &str) -> Response<Body> {
    let Some(token) = query_value(full_path, "token") else {
        return text(StatusCode::BAD_REQUEST, "missing step-up token");
    };
    let Some(challenge) = auth::pending_step_up_challenge(state, &token) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired step-up request",
        );
    };
    let cfg = state.cfg().auth;
    json_response(json!({
        "ok": true,
        "factor": challenge.factor,
        "reason": challenge.reason,
        "return_to": challenge.return_to,
        "user": {
            "sub": challenge.user.sub,
            "name": challenge.user.name,
            "email": challenge.user.email,
        },
        "passkey_registered": cfg.passkeys.iter().any(|record| record.user_sub == challenge.user.sub),
        "totp_registered": cfg.totp_factors.iter().any(|record| record.user_sub == challenge.user.sub),
    }))
}

pub(super) fn step_up_totp_setup_start(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some((token, challenge)) = totp_challenge_from_payload(state, &payload) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired TOTP step-up request",
        );
    };
    let secret = totp::generate_secret();
    let label = totp_label(&challenge);
    let request_id = random_hex(16);
    {
        let mut pending = lock_mutex(&state.totp_registrations, "totp registrations");
        prune_totp_registrations(&mut pending);
        pending.insert(
            request_id.clone(),
            PendingTotpRegistration {
                ts: crate::util::now_epoch(),
                user_sub: challenge.user.sub,
                user_name: challenge.user.name,
                user_email: challenge.user.email,
                label: label.clone(),
                step_up: token,
                secret: secret.clone(),
            },
        );
    }
    json_response(json!({
        "ok": true,
        "request_id": request_id,
        "secret": secret,
        "otpauth_uri": totp::otpauth_uri(&label, "klaxond", &secret),
    }))
}

pub(super) fn step_up_totp_setup_confirm(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let code = payload.get("code").and_then(Value::as_str).unwrap_or("");
    let Some(pending) = pending_totp_registration(state, request_id) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired TOTP setup request",
        );
    };
    let Some(counter) = totp::verify_code_counter(&pending.secret, code.trim(), now_epoch_i64())
    else {
        return text(StatusCode::BAD_REQUEST, "invalid TOTP code");
    };
    complete_totp_setup(state, request_id, pending, counter)
}

pub(super) fn step_up_totp_verify(state: &AppState, body: Bytes) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some((token, challenge)) = totp_challenge_from_payload(state, &payload) else {
        return text(
            StatusCode::BAD_REQUEST,
            "unknown or expired TOTP step-up request",
        );
    };
    let code = payload.get("code").and_then(Value::as_str).unwrap_or("");
    match consume_totp_factor(state, &challenge.user.sub, code.trim()) {
        Ok(true) => complete_totp_step_up(state, &token, &challenge.user.sub),
        Ok(false) => text(StatusCode::UNAUTHORIZED, "invalid or replayed TOTP code"),
        Err(err) => text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
}

fn totp_challenge_from_payload(
    state: &AppState,
    payload: &Value,
) -> Option<(String, StepUpChallenge)> {
    let token = payload
        .get("step_up")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let challenge = auth::pending_step_up_challenge(state, &token)?;
    (challenge.factor == "totp").then_some((token, challenge))
}

fn pending_totp_registration(
    state: &AppState,
    request_id: &str,
) -> Option<PendingTotpRegistration> {
    let mut pending = lock_mutex(&state.totp_registrations, "totp registrations");
    prune_totp_registrations(&mut pending);
    pending.get(request_id).cloned()
}

fn complete_totp_setup(
    state: &AppState,
    request_id: &str,
    pending: PendingTotpRegistration,
    counter: u64,
) -> Response<Body> {
    let record = match state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let record = totp_record(&pending, counter);
        cfg.auth
            .totp_factors
            .retain(|existing| existing.user_sub != record.user_sub);
        cfg.auth.totp_factors.push(record.clone());
        if let Err(err) = save_auth(&state.paths, &cfg.auth) {
            return Err(err.to_string());
        }
        state.replace_config(cfg);
        lock_mutex(&state.totp_registrations, "totp registrations").remove(request_id);
        Ok(record)
    }) {
        Ok(Ok(record)) => record,
        Ok(Err(err)) | Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, &err),
    };
    issue_totp_step_up_session(state, &pending.step_up, &record.user_sub)
}

fn complete_totp_step_up(state: &AppState, token: &str, user_sub: &str) -> Response<Body> {
    issue_totp_step_up_session(state, token, user_sub)
}

fn issue_totp_step_up_session(state: &AppState, token: &str, user_sub: &str) -> Response<Body> {
    let (mut user, return_to) = match auth::finish_totp_step_up(state, token, user_sub) {
        Ok(finished) => finished,
        Err(err) => return text(StatusCode::UNAUTHORIZED, &err),
    };
    let cookie = match auth::issue_session_cookie(state, &mut user) {
        Ok(cookie) => cookie,
        Err(err) => {
            tracing::error!("persist TOTP step-up session failed: {err}");
            return text(StatusCode::SERVICE_UNAVAILABLE, "session store unavailable");
        }
    };
    let mut resp = json_response(json!({"ok": true, "user": user, "return_to": return_to}));
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, value);
    }
    resp
}

fn consume_totp_factor(state: &AppState, user_sub: &str, code: &str) -> Result<bool, String> {
    state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let Some(record) = cfg
            .auth
            .totp_factors
            .iter_mut()
            .find(|record| record.user_sub == user_sub)
        else {
            return Ok(false);
        };
        let now = now_epoch_i64();
        let Some(counter) = totp::verify_code_counter(&record.secret, code, now) else {
            return Ok(false);
        };
        if record.last_used_counter.is_some_and(|last| counter <= last) {
            return Ok(false);
        }
        record.last_used_counter = Some(counter);
        record.last_used_at = Some(now);
        save_auth(&state.paths, &cfg.auth).map_err(|err| err.to_string())?;
        state.replace_config(cfg);
        Ok(true)
    })?
}

fn prune_totp_registrations(
    pending: &mut std::collections::HashMap<String, PendingTotpRegistration>,
) {
    let cutoff = crate::util::now_epoch() - STEP_UP_TOTP_TTL_SECONDS;
    pending.retain(|_, registration| registration.ts >= cutoff);
}

fn totp_record(pending: &PendingTotpRegistration, counter: u64) -> TotpRecord {
    TotpRecord {
        id: random_hex(8),
        name: pending.label.clone(),
        user_sub: pending.user_sub.clone(),
        user_name: pending.user_name.clone(),
        user_email: pending.user_email.clone(),
        secret: pending.secret.clone(),
        created_at: now_epoch_i64(),
        last_used_at: Some(now_epoch_i64()),
        last_used_counter: Some(counter),
    }
}

fn totp_label(challenge: &StepUpChallenge) -> String {
    let account = if !challenge.user.email.trim().is_empty() {
        challenge.user.email.trim()
    } else if !challenge.user.name.trim().is_empty() {
        challenge.user.name.trim()
    } else {
        challenge.user.sub.trim()
    };
    format!("klaxond:{account}")
}

fn query_value(path: &str, key: &str) -> Option<String> {
    Url::parse(&format!("http://localhost{path}"))
        .ok()?
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.to_string())
}
