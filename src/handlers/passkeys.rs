use super::{json_body, json_response, text};
use crate::audit;
use crate::auth::{self, User};
use crate::config::{PasskeyRecord, RuntimeConfig, save_auth};
use crate::state::{
    AppState, PendingPasskeyAuthentication, PendingPasskeyRegistration, lock_mutex,
};
use crate::util::random_hex;
use auth_modules::rate_limit::{GOLD_AUTH_ACCOUNT_FAILURE_MAX, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW};
use axum::body::{Body, Bytes};
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use url::Url;
use webauthn_rs::prelude::{
    CredentialID, Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn,
    WebauthnBuilder,
};

fn webauthn_for_cfg(cfg: &RuntimeConfig) -> Result<Webauthn, String> {
    if !cfg.auth.webauthn.enabled {
        return Err("WebAuthn/passkeys are disabled".into());
    }
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let url = Url::parse(&origin).map_err(|err| format!("invalid WebAuthn origin: {err}"))?;
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        url.domain()
            .ok_or_else(|| "WebAuthn origin must have a domain host".to_string())?
            .to_string()
    } else {
        cfg.auth.webauthn.rp_id.trim().to_string()
    };
    WebauthnBuilder::new(&rp_id, &url)
        .map_err(|err| format!("invalid WebAuthn relying party: {err}"))?
        .rp_name("klaxond")
        .allow_any_port(matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        ))
        .build()
        .map_err(|err| format!("invalid WebAuthn config: {err}"))
}

pub(super) fn webauthn_public_config(cfg: &RuntimeConfig) -> Value {
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        Url::parse(&origin)
            .ok()
            .and_then(|url| url.domain().map(ToOwned::to_owned))
            .unwrap_or_default()
    } else {
        cfg.auth.webauthn.rp_id.clone()
    };
    json!({
        "enabled": cfg.auth.webauthn.enabled,
        "rp_id": rp_id,
        "origin": origin,
    })
}

pub(super) fn public_passkey(record: &PasskeyRecord) -> Value {
    json!({
        "id": record.id,
        "name": record.name,
        "user_sub": record.user_sub,
        "user_name": record.user_name,
        "user_email": record.user_email,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
    })
}

pub(super) fn passkey_register_start(
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
    let label = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("passkey")
        .trim()
        .chars()
        .take(80)
        .collect::<String>();
    let cfg = state.cfg();
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let excludes = cfg
        .auth
        .passkeys
        .iter()
        .filter(|p| p.user_sub == user.sub)
        .map(|p| p.credential.cred_id().clone())
        .collect::<Vec<CredentialID>>();
    let user_uuid = Uuid::new_v4();
    let display_name = if user.name.is_empty() {
        user.sub.as_str()
    } else {
        user.name.as_str()
    };
    let (challenge, reg_state) = match webauthn.start_passkey_registration(
        user_uuid,
        &user.sub,
        display_name,
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
                state: reg_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

pub(super) fn passkey_register_finish(state: &AppState, body: Bytes) -> Response<Body> {
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
    let pending = {
        let mut pending = lock_mutex(&state.passkey_registrations, "passkey registrations");
        match pending.remove(request_id) {
            Some(v) => v,
            None => {
                return text(
                    StatusCode::BAD_REQUEST,
                    "unknown or expired passkey request",
                );
            }
        }
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
            let record = PasskeyRecord {
                id: random_hex(8),
                name: pending.label,
                user_sub: pending.user_sub,
                user_name: pending.user_name,
                user_email: pending.user_email,
                user_uuid: pending.user_uuid.to_string(),
                created_at: crate::util::now_epoch_i64(),
                last_used_at: None,
                credential: passkey,
            };
            cfg.auth.passkeys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true, "passkey": public_passkey(&record)}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(super) fn passkey_login_start(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    body: Bytes,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let user_hint = payload
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let rate_key = passkey_auth_rate_key("passkey", &user_hint, headers, peer);
    if passkey_auth_rate_limited(state, &rate_key) {
        record_passkey_auth_failure(state, &rate_key, "rate_limited");
        return passkey_auth_rate_limited_response();
    }
    if user_hint.is_empty() {
        record_passkey_auth_failure(state, &rate_key, "missing user");
        return text(StatusCode::BAD_REQUEST, "user is required");
    }
    let cfg = state.cfg();
    let matching = cfg
        .auth
        .passkeys
        .iter()
        .filter(|record| {
            [
                record.user_sub.as_str(),
                record.user_name.as_str(),
                record.user_email.as_str(),
            ]
            .iter()
            .any(|v| v.to_ascii_lowercase() == user_hint)
        })
        .cloned()
        .collect::<Vec<_>>();
    if matching.is_empty() {
        record_passkey_auth_failure(state, &rate_key, "no passkey registered for user");
        return text(StatusCode::NOT_FOUND, "no passkey registered for that user");
    }
    let webauthn = match webauthn_for_cfg(&cfg) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &err),
    };
    let creds = matching
        .iter()
        .map(|record| record.credential.clone())
        .collect::<Vec<Passkey>>();
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
                user_sub: matching[0].user_sub.clone(),
                rate_key,
                state: auth_state,
            },
        );
    }
    json_response(json!({"ok": true, "request_id": request_id, "publicKey": challenge.public_key}))
}

pub(super) fn passkey_login_finish(
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
    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(credential_value) = payload.get("credential") else {
        return text(StatusCode::BAD_REQUEST, "missing credential");
    };
    let credential: PublicKeyCredential = match serde_json::from_value(credential_value.clone()) {
        Ok(v) => v,
        Err(err) => return text(StatusCode::BAD_REQUEST, &format!("bad credential: {err}")),
    };
    let pending = {
        let mut pending = lock_mutex(&state.passkey_authentications, "passkey authentications");
        match pending.remove(request_id) {
            Some(v) => v,
            None => {
                record_passkey_auth_failure(state, &unknown_rate_key, "unknown passkey request");
                return text(
                    StatusCode::BAD_REQUEST,
                    "unknown or expired passkey request",
                );
            }
        }
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
    let result = match webauthn.finish_passkey_authentication(&credential, &pending.state) {
        Ok(v) => v,
        Err(err) => {
            record_passkey_auth_failure(state, &pending.rate_key, "passkey verification failed");
            return text(StatusCode::UNAUTHORIZED, &err.to_string());
        }
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let now = crate::util::now_epoch_i64();
            let mut matched_idx = None;
            for (idx, record) in cfg.auth.passkeys.iter_mut().enumerate() {
                if record.user_sub == pending.user_sub
                    && record.credential.update_credential(&result).is_some()
                {
                    matched_idx = Some(idx);
                    break;
                }
            }
            let Some(idx) = matched_idx else {
                record_passkey_auth_failure(state, &pending.rate_key, "passkey credential missing");
                return text(StatusCode::UNAUTHORIZED, "passkey credential not found");
            };
            let record = &mut cfg.auth.passkeys[idx];
            record.last_used_at = Some(now);
            let mut user = User {
                sub: record.user_sub.clone(),
                email: record.user_email.clone(),
                name: record.user_name.clone(),
                groups: vec!["passkey".into()],
                mode: "passkey".into(),
                exp: 0,
                csrf: String::new(),
                sudo_until: auth::sudo_until_deadline(),
                via_authorization: false,
            };
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            let cookie = auth::issue_session_cookie(state, &mut user);
            clear_passkey_auth_failures(state, &pending.rate_key);
            let mut resp = json_response(json!({"ok": true, "user": user}));
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(SET_COOKIE, value);
            }
            resp
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn passkey_auth_rate_key(
    action: &str,
    subject: &str,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> String {
    let subject = subject.trim().to_ascii_lowercase();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
        .unwrap_or_else(|| peer.ip().to_string());
    format!(
        "{action}:{}:{ip}",
        if subject.is_empty() {
            "unknown"
        } else {
            subject.as_str()
        }
    )
}

fn passkey_auth_rate_limited(state: &AppState, rate_key: &str) -> bool {
    state.auth_failures.blocked(
        rate_key,
        GOLD_AUTH_ACCOUNT_FAILURE_MAX,
        GOLD_AUTH_ACCOUNT_FAILURE_WINDOW,
    )
}

fn record_passkey_auth_failure(state: &AppState, rate_key: &str, detail: &'static str) {
    state
        .auth_failures
        .record(rate_key, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW);
    audit::record(
        rate_key.to_string(),
        "auth.passkey",
        "error",
        detail.to_string(),
    );
}

fn clear_passkey_auth_failures(state: &AppState, rate_key: &str) {
    state.auth_failures.clear(rate_key);
}

fn passkey_auth_rate_limited_response() -> Response<Body> {
    text(
        StatusCode::TOO_MANY_REQUESTS,
        "too many authentication failures",
    )
}

pub(super) fn passkey_delete(
    state: &AppState,
    id: &str,
    current_user: Option<&User>,
) -> Response<Body> {
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "passkey id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let before = cfg.auth.passkeys.len();
            cfg.auth.passkeys.retain(|record| {
                if record.id != id {
                    return true;
                }
                if let Some(user) = current_user
                    && user.mode == "passkey"
                    && user.sub != record.user_sub
                {
                    return true;
                }
                false
            });
            if cfg.auth.passkeys.len() == before {
                return text(StatusCode::NOT_FOUND, "passkey not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(super) fn passkey_login_page() -> Response<Body> {
    let html = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>klaxond passkey login</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="passkey-login"><section class="card"><h1>klaxond</h1><h2>Passkey login</h2>
<label>User, email or subject <input id="user" autocomplete="username webauthn"></label>
<button id="login" class="primary">Use passkey</button><p id="status" class="muted"></p>
<p><a href="/status">Back to UI</a></p></section></main>
<script>
const b64uToBuf=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');s+='==='.slice((s.length+3)%4);const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer};
const bufToB64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function publicKeyGetOptions(pk){pk.challenge=b64uToBuf(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));return pk}
function credentialGetPayload(c){return {id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{authenticatorData:bufToB64u(c.response.authenticatorData),clientDataJSON:bufToB64u(c.response.clientDataJSON),signature:bufToB64u(c.response.signature),userHandle:c.response.userHandle?bufToB64u(c.response.userHandle):null},extensions:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
document.getElementById('login').onclick=async()=>{const s=document.getElementById('status');try{const user=document.getElementById('user').value.trim();const a=await fetch('/api/auth/passkey/login/options',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user})});if(!a.ok)throw new Error(await a.text());const ch=await a.json();const cred=await navigator.credentials.get({publicKey:publicKeyGetOptions(ch.publicKey)});const f=await fetch('/api/auth/passkey/login/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:ch.request_id,credential:credentialGetPayload(cred)})});if(!f.ok)throw new Error(await f.text());location.href='/status'}catch(e){s.textContent=e.message||String(e);s.style.color='var(--red)'}};
</script></body></html>"#;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}
