#[cfg(test)]
mod tests;

mod redaction;
mod validation;

use super::{json_body, json_response, text};
use crate::auth::{self, User};
use crate::config::{AuthConfig, save_auth};
use crate::state::AppState;
use auth_modules::methods::{
    API_TOKEN, HARDWARE_KEY, LDAP, MAGIC_LINK, OIDC, PASSKEY, PASSWORD, TOTP, TRUSTED_PROXY,
    canonical_auth_method_statuses,
};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;

mod patch;
mod tokens;

use patch::{AuthConfigPatchError, AuthSettingsPatch};
pub(super) use tokens::{create_auth_token, password_policy_response, revoke_auth_token};

pub(super) fn anonymous_user() -> User {
    User {
        sub: "anonymous".into(),
        email: String::new(),
        name: String::new(),
        groups: vec![],
        mode: "none".into(),
        exp: 0,
        csrf: String::new(),
        sudo_until: 0,
        via_authorization: false,
        second_factor: String::new(),
        session_id_hash: String::new(),
        session_family_hash: String::new(),
        session_created_at: 0,
        provider_issuer: String::new(),
        provider_session_id: String::new(),
    }
}

pub(super) use redaction::redacted_auth_settings;

pub(super) fn auth_methods_payload(auth_cfg: &AuthConfig) -> Value {
    let mode = auth_cfg.mode.as_str();
    let methods: Vec<_> = canonical_auth_method_statuses(|method| match method {
        PASSWORD => mode == "basic" && !auth_cfg.basic.password_hash.is_empty(),
        OIDC => {
            mode == "oidc"
                && !auth_cfg.oidc.issuer.is_empty()
                && !auth_cfg.oidc.client_id.is_empty()
        }
        TOTP => {
            (mode == "basic" && auth_cfg.basic.totp_enabled)
                || (auth_cfg.step_up.required_after_primary && auth_cfg.step_up.factor == TOTP)
                || !auth_cfg.totp_factors.is_empty()
        }
        PASSKEY => auth_cfg.webauthn.enabled,
        HARDWARE_KEY => auth_cfg.webauthn.enabled,
        TRUSTED_PROXY => mode == "trusted-proxy",
        LDAP => auth::ldap_login_enabled(auth_cfg),
        API_TOKEN => mode != "none",
        MAGIC_LINK => auth::magic_link_enabled(auth_cfg),
        _ => false,
    })
    .into_iter()
    .map(|row| json!({ "method": row.method, "enabled": row.enabled }))
    .collect();
    json!({
        "methods": methods,
        "step_up": {
            "required_after_primary": auth_cfg.step_up.required_after_primary,
            "factor": auth_cfg.step_up.factor.as_str(),
        }
    })
}
use validation::validate_auth_config;

fn auth_patch_error_response(err: AuthConfigPatchError) -> Response<Body> {
    match err {
        AuthConfigPatchError::InvalidMode => text(StatusCode::BAD_REQUEST, "invalid mode"),
        AuthConfigPatchError::PasswordPolicy(message) => text(StatusCode::BAD_REQUEST, &message),
        AuthConfigPatchError::HashPassword(message) => {
            text(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
    }
}

pub(super) fn update_auth_config(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let Some(incoming) = payload.get("settings") else {
        return text(StatusCode::BAD_REQUEST, "missing 'settings' object");
    };
    let patch = serde_json::from_value::<AuthSettingsPatch>(incoming.clone()).unwrap_or_default();
    state
        .with_config_write_lock(|| {
            let mut auth = state.cfg().auth;
            if let Err(err) = patch.apply_to(&mut auth) {
                return auth_patch_error_response(err);
            }
            if let Err(err) = validate_auth_config(&auth, current_user, peer, headers) {
                return text(StatusCode::BAD_REQUEST, &err);
            }
            if let Err(err) = save_auth(&state.paths, &auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            let mut cfg = state.cfg();
            cfg.auth = auth;
            let redacted = redacted_auth_settings(&cfg.auth);
            state.replace_config(cfg);
            json_response(json!({"ok": true, "settings": redacted}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}
