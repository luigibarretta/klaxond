use super::passkeys::public_passkey;
#[cfg(test)]
mod tests;

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
use ipnet::IpNet;
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};

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
    }
}

pub(super) fn redacted_auth_settings(auth_cfg: &AuthConfig) -> Value {
    let mut settings = serde_json::to_value(auth_cfg).unwrap_or_else(|_| json!({}));
    if !settings["session_secret"].as_str().unwrap_or("").is_empty() {
        settings["session_secret"] = json!("***SET***");
    }
    if !settings["basic"]["password_hash"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        settings["basic"]["password_hash"] = json!("***SET***");
    }
    if !settings["basic"]["totp_secret"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        settings["basic"]["totp_secret"] = json!("***SET***");
    }
    if let Some(basic) = settings["basic"].as_object_mut() {
        basic.remove("totp_last_counter");
    }
    if !settings["oidc"]["client_secret"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        settings["oidc"]["client_secret"] = json!("***SET***");
    }
    if !settings["ldap"]["service_bind_password"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        settings["ldap"]["service_bind_password"] = json!("***SET***");
    }
    settings["api_keys"] = json!(
        auth_cfg
            .api_keys
            .iter()
            .map(auth::public_token)
            .collect::<Vec<_>>()
    );
    settings["passkeys"] = json!(
        auth_cfg
            .passkeys
            .iter()
            .map(public_passkey)
            .collect::<Vec<_>>()
    );
    settings["totp_factors"] = json!(
        auth_cfg
            .totp_factors
            .iter()
            .map(|record| json!({
                "id": record.id.as_str(),
                "name": record.name.as_str(),
                "user_sub": record.user_sub.as_str(),
                "user_name": record.user_name.as_str(),
                "user_email": record.user_email.as_str(),
                "created_at": record.created_at,
                "last_used_at": record.last_used_at,
            }))
            .collect::<Vec<_>>()
    );
    settings
}

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
fn validate_auth_config(
    auth: &AuthConfig,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), String> {
    if auth.step_up.required_after_primary
        && matches!(auth.step_up.factor.as_str(), PASSKEY | HARDWARE_KEY)
        && !auth.webauthn.enabled
    {
        return Err("MFA / step-up with passkeys requires WebAuthn/passkeys to be enabled".into());
    }
    match auth.mode.as_str() {
        "none" => Ok(()),
        "basic" => {
            if auth.basic.username.trim().is_empty() {
                return Err("basic auth requires a username".into());
            }
            if auth.basic.password_hash.trim().is_empty() {
                return Err("basic auth requires a password before it can be enabled".into());
            }
            if auth.basic.totp_enabled && auth.basic.totp_secret.trim().is_empty() {
                return Err("basic auth TOTP is enabled but no TOTP secret is configured".into());
            }
            Ok(())
        }
        "ldap" => {
            if !(auth.ldap.url.starts_with("ldap://") || auth.ldap.url.starts_with("ldaps://")) {
                return Err("LDAP requires an ldap:// or ldaps:// URL".into());
            }
            if auth_modules::ldap::ldap_scope_from_name(&auth.ldap.scope).is_none() {
                return Err("LDAP scope must be base, one, or subtree".into());
            }
            if auth.ldap.to_auth_modules_config().is_none() {
                return Err(
                    "LDAP requires either bind_dn_template or service bind DN/password".into(),
                );
            }
            Ok(())
        }
        "oidc" => {
            if auth.oidc.issuer.trim().is_empty() || auth.oidc.client_id.trim().is_empty() {
                return Err("OIDC requires issuer and client_id before it can be enabled".into());
            }
            if auth.oidc.redirect_path != "/api/auth/callback" {
                return Err("OIDC redirect_path must be /api/auth/callback".into());
            }
            if let Some(user) = current_user
                && !auth.oidc.required_group.trim().is_empty()
                && user.mode == "oidc"
                && !user.groups.iter().any(|g| g == &auth.oidc.required_group)
            {
                return Err(format!(
                    "current OIDC user is not in required_group '{}'",
                    auth.oidc.required_group
                ));
            }
            Ok(())
        }
        "trusted-proxy" => {
            if auth.trusted_proxy.user_header.trim().is_empty() {
                return Err("trusted-proxy requires a user header".into());
            }
            if auth.trusted_proxy.trusted_cidrs.is_empty() {
                return Err("trusted-proxy requires at least one trusted CIDR".into());
            }
            for cidr in &auth.trusted_proxy.trusted_cidrs {
                cidr.parse::<IpNet>()
                    .map_err(|_| format!("invalid trusted CIDR '{cidr}'"))?;
            }
            if !cidr_match(peer.ip(), &auth.trusted_proxy.trusted_cidrs) {
                return Err(format!(
                    "current peer {} is not covered by trusted_proxy.trusted_cidrs",
                    peer.ip()
                ));
            }
            if headers
                .get(auth.trusted_proxy.user_header.as_str())
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.trim().is_empty())
                .is_none()
            {
                return Err(format!(
                    "current request is missing trusted proxy user header '{}'",
                    auth.trusted_proxy.user_header
                ));
            }
            Ok(())
        }
        _ => Err("invalid mode".into()),
    }
}

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

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
