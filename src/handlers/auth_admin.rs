use super::passkeys::public_passkey;
use super::{json_body, json_response, text};
use crate::auth::{self, User};
use crate::config::{AuthConfig, AuthToken, save_auth};
use crate::state::AppState;
use crate::util::{random_hex, token_urlsafe};
use auth_modules::methods::{
    API_TOKEN, HARDWARE_KEY, LDAP, MAGIC_LINK, OIDC, PASSKEY, PASSWORD, TOTP, TRUSTED_PROXY,
    canonical_auth_method_statuses,
};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use ipnet::IpNet;
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};

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
        TOTP => mode == "basic" && auth_cfg.basic.totp_enabled,
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
        "methods": methods
    })
}
fn validate_auth_config(
    auth: &AuthConfig,
    current_user: Option<&User>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), String> {
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
    state
        .with_config_write_lock(|| {
            let mut auth = state.cfg().auth;
            if let Some(mode) = incoming.get("mode").and_then(|v| v.as_str()) {
                if !matches!(mode, "none" | "basic" | "ldap" | "oidc" | "trusted-proxy") {
                    return text(StatusCode::BAD_REQUEST, "invalid mode");
                }
                auth.mode = mode.into();
            }
            if let Some(h) = incoming
                .get("session_timeout_hours")
                .and_then(|v| v.as_u64())
            {
                auth.session_timeout_hours = h.clamp(1, 720);
            }
            if let Some(v) = incoming
                .get("session_secret")
                .and_then(|v| v.as_str())
                .filter(|v| *v != "***SET***")
            {
                auth.session_secret = v.into();
            }
            if let Some(b) = incoming.get("basic").and_then(|v| v.as_object()) {
                if let Some(v) = b.get("username").and_then(|v| v.as_str()) {
                    auth.basic.username = v.into();
                }
                if let Some(v) = b.get("realm").and_then(|v| v.as_str()) {
                    auth.basic.realm = v.into();
                }
                if let Some(pwd) = b
                    .get("password")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    if let Err(error) =
                        auth::validate_password_policy(pwd, Some(&auth.basic.username))
                    {
                        return text(StatusCode::BAD_REQUEST, &error.message());
                    }
                    match auth::hash_password(pwd) {
                        Ok(h) => auth.basic.password_hash = h,
                        Err(err) => {
                            return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
                        }
                    }
                } else if let Some(h) = b
                    .get("password_hash")
                    .and_then(|v| v.as_str())
                    .filter(|s| *s != "***SET***" && !s.is_empty())
                {
                    auth.basic.password_hash = h.into();
                }
            }
            if let Some(o) = incoming.get("oidc").and_then(|v| v.as_object()) {
                for (k, slot) in [
                    ("provider", &mut auth.oidc.provider),
                    ("issuer", &mut auth.oidc.issuer),
                    ("client_id", &mut auth.oidc.client_id),
                    ("scopes", &mut auth.oidc.scopes),
                    ("required_group", &mut auth.oidc.required_group),
                    ("redirect_path", &mut auth.oidc.redirect_path),
                ] {
                    if let Some(v) = o.get(k).and_then(|v| v.as_str()) {
                        *slot = v.into();
                    }
                }
                if let Some(v) = o
                    .get("client_secret")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && *s != "***SET***")
                {
                    auth.oidc.client_secret = v.into();
                }
            }
            if let Some(ldap) = incoming.get("ldap").and_then(|v| v.as_object()) {
                for (key, slot) in [
                    ("url", &mut auth.ldap.url),
                    ("bind_dn_template", &mut auth.ldap.bind_dn_template),
                    ("service_bind_dn", &mut auth.ldap.service_bind_dn),
                    ("base_dn", &mut auth.ldap.base_dn),
                    ("user_filter", &mut auth.ldap.user_filter),
                    ("scope", &mut auth.ldap.scope),
                    ("username_attr", &mut auth.ldap.username_attr),
                    ("email_attr", &mut auth.ldap.email_attr),
                    ("name_attr", &mut auth.ldap.name_attr),
                    ("groups_attr", &mut auth.ldap.groups_attr),
                ] {
                    if let Some(v) = ldap.get(key).and_then(|v| v.as_str()) {
                        *slot = v.trim().to_string();
                    }
                }
                if let Some(v) = ldap
                    .get("service_bind_password")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && *s != "***SET***")
                {
                    auth.ldap.service_bind_password = v.to_string();
                }
                if let Some(v) = ldap.get("timeout_secs").and_then(|v| v.as_u64()) {
                    auth.ldap.timeout_secs = v.clamp(1, 60);
                }
            }
            if let Some(tp) = incoming.get("trusted_proxy").and_then(|v| v.as_object()) {
                if let Some(v) = tp.get("user_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.user_header = v.into();
                }
                if let Some(v) = tp.get("email_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.email_header = v.into();
                }
                if let Some(v) = tp.get("groups_header").and_then(|v| v.as_str()) {
                    auth.trusted_proxy.groups_header = v.into();
                }
                if let Some(arr) = tp.get("trusted_cidrs").and_then(|v| v.as_array()) {
                    auth.trusted_proxy.trusted_cidrs = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
            if let Some(w) = incoming.get("webauthn").and_then(|v| v.as_object()) {
                if let Some(v) = w.get("enabled").and_then(|v| v.as_bool()) {
                    auth.webauthn.enabled = v;
                }
                if let Some(v) = w.get("rp_id").and_then(|v| v.as_str()) {
                    auth.webauthn.rp_id = v.trim().to_string();
                }
                if let Some(v) = w.get("origin").and_then(|v| v.as_str()) {
                    auth.webauthn.origin = v.trim().trim_end_matches('/').to_string();
                }
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

pub(super) fn create_auth_token(
    state: &AppState,
    body: Bytes,
    current_user: Option<&User>,
) -> Response<Body> {
    let Ok(payload) = json_body(&body) else {
        return text(StatusCode::BAD_REQUEST, "bad json");
    };
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token name is required");
    }
    let kind = payload
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("api-key")
        .trim();
    if !matches!(kind, "api-key" | "pat") {
        return text(StatusCode::BAD_REQUEST, "kind must be api-key or pat");
    }
    let scopes = payload
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if scopes.is_empty() {
        return text(StatusCode::BAD_REQUEST, "at least one scope is required");
    }
    for scope in &scopes {
        if !auth::TOKEN_SCOPES.contains(&scope.as_str()) {
            return text(StatusCode::BAD_REQUEST, &format!("invalid scope '{scope}'"));
        }
    }
    if !token_scopes_allowed_for_actor(current_user, &scopes) {
        return text(
            StatusCode::FORBIDDEN,
            "requested token scopes exceed the authenticated token scope",
        );
    }
    let now = crate::util::now_epoch_i64();
    let expires_at = payload
        .get("expires_in_days")
        .and_then(|v| v.as_u64())
        .filter(|days| *days > 0)
        .map(|days| now + (days.min(3650) * 86_400) as i64)
        .or_else(|| {
            payload
                .get("expires_at")
                .and_then(|v| v.as_i64())
                .filter(|v| *v > now)
        });
    let token = format!(
        "klx_{}_{}",
        if kind == "pat" { "pat" } else { "key" },
        token_urlsafe(32)
    );
    let record = AuthToken {
        id: random_hex(8),
        name: name.to_string(),
        kind: kind.to_string(),
        prefix: token.chars().take(18).collect(),
        token_hash: auth::token_hash(&token),
        scopes,
        created_at: now,
        expires_at,
        last_used_at: None,
        enabled: true,
    };
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            cfg.auth.api_keys.push(record.clone());
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({
                "ok": true,
                "token": token,
                "record": auth::public_token(&record),
            }))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

fn token_scopes_allowed_for_actor(current_user: Option<&User>, requested: &[String]) -> bool {
    let Some(user) = current_user else {
        return true;
    };
    if !user.via_authorization {
        return true;
    }
    requested
        .iter()
        .all(|scope| auth::scopes_allow(&user.groups, scope))
}

pub(super) fn revoke_auth_token(state: &AppState, id: &str) -> Response<Body> {
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "token id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let mut changed = false;
            for token in &mut cfg.auth.api_keys {
                if token.id == id {
                    token.enabled = false;
                    changed = true;
                }
            }
            if !changed {
                return text(StatusCode::NOT_FOUND, "token not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}

pub(super) fn password_policy_response() -> Response<Body> {
    let profile = auth_modules::security_profile::GoldAuthProfile::personal_default();
    let policy = profile.password_policy;
    json_response(json!({
        "min_length": policy.min_length,
        "max_length": policy.max_length,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_methods_payload_maps_hardware_key_and_magic_link() {
        let mut auth = AuthConfig::default();
        auth.mode = "basic".to_string();
        auth.basic.username = "luigi".to_string();
        auth.basic.password_hash = "$argon2id$configured".to_string();
        auth.basic.totp_enabled = true;
        auth.webauthn.enabled = true;

        let payload = auth_methods_payload(&auth);
        let actual = payload["methods"]
            .as_array()
            .expect("methods")
            .iter()
            .map(|row| {
                (
                    row["method"].as_str().expect("method"),
                    row["enabled"].as_bool().expect("enabled"),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                ("password", true),
                ("oidc", false),
                ("totp", true),
                ("passkey", true),
                ("hardware_key", true),
                ("trusted_proxy", false),
                ("ldap", false),
                ("api_token", true),
                ("magic_link", true),
            ]
        );
    }

    #[test]
    fn auth_methods_payload_enables_configured_ldap() {
        let mut auth = AuthConfig::default();
        auth.mode = "ldap".to_string();
        auth.ldap.url = "ldaps://directory.example.com:636".to_string();
        auth.ldap.bind_dn_template = "uid={username},ou=people,dc=example,dc=com".to_string();

        let payload = auth_methods_payload(&auth);
        let methods = payload["methods"].as_array().expect("methods");

        assert!(
            methods
                .iter()
                .any(|row| row["method"] == "ldap" && row["enabled"] == true)
        );
        assert!(
            methods
                .iter()
                .any(|row| row["method"] == "password" && row["enabled"] == false)
        );
    }
}
