use super::{AuthConfig, Paths};
use crate::util::atomic_write_json;
use anyhow::Result;
use std::fs;

pub(super) fn load_auth(paths: &Paths, seed: Option<&toml::Value>) -> Result<AuthConfig> {
    let mut out = AuthConfig::default();
    if paths.auth_config.exists() {
        let raw: AuthConfig = serde_json::from_slice(&fs::read(&paths.auth_config)?)?;
        out = merge_auth(out, raw);
    } else {
        if let Some(seed) = seed {
            out = merge_auth_toml(out, seed);
        }
        if let Ok(sec) = std::env::var("AUTH_OIDC_CLIENT_SECRET")
            && !sec.is_empty()
        {
            out.oidc.client_secret = sec;
        }
        if let Ok(hash) = std::env::var("AUTH_BASIC_PASSWORD_HASH")
            && !hash.is_empty()
        {
            out.basic.password_hash = hash;
        }
        save_auth(paths, &out)?;
    }
    if normalize_auth_config(&mut out) {
        save_auth(paths, &out)?;
    }
    Ok(out)
}

pub fn save_auth(paths: &Paths, auth: &AuthConfig) -> Result<()> {
    atomic_write_json(&paths.auth_config, auth)
}

fn merge_auth(mut base: AuthConfig, raw: AuthConfig) -> AuthConfig {
    base.mode = raw.mode;
    base.session_secret = raw.session_secret;
    base.session_timeout_hours = raw.session_timeout_hours;
    base.basic = raw.basic;
    base.oidc = raw.oidc;
    base.ldap = raw.ldap;
    base.trusted_proxy = raw.trusted_proxy;
    base.webauthn = raw.webauthn;
    base.api_keys = raw.api_keys;
    base.passkeys = raw.passkeys;
    base
}

fn normalize_auth_config(auth: &mut AuthConfig) -> bool {
    let mut changed = false;
    let issuer = auth.oidc.issuer.trim().to_string();
    if issuer != auth.oidc.issuer {
        auth.oidc.issuer = issuer;
        changed = true;
    }
    if auth.oidc.redirect_path == "/auth/callback" {
        auth.oidc.redirect_path = "/api/auth/callback".to_string();
        changed = true;
    }
    changed
}

pub(super) fn merge_auth_toml(mut base: AuthConfig, seed: &toml::Value) -> AuthConfig {
    if let Some(mode) = seed.get("mode").and_then(|v| v.as_str()) {
        base.mode = mode.to_string();
    }
    if let Some(secret) = seed.get("session_secret").and_then(|v| v.as_str()) {
        base.session_secret = secret.to_string();
    }
    if let Some(h) = seed
        .get("session_timeout_hours")
        .and_then(|v| v.as_integer())
    {
        base.session_timeout_hours = h.max(1) as u64;
    }
    for (section, setter) in [
        ("basic", 0_usize),
        ("oidc", 1_usize),
        ("ldap", 2_usize),
        ("trusted_proxy", 3_usize),
    ] {
        let Some(t) = seed.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        match setter {
            0 => {
                if let Some(v) = t.get("username").and_then(|v| v.as_str()) {
                    base.basic.username = v.to_string();
                }
                if let Some(v) = t.get("password_hash").and_then(|v| v.as_str()) {
                    base.basic.password_hash = v.to_string();
                }
                if let Some(v) = t.get("realm").and_then(|v| v.as_str()) {
                    base.basic.realm = v.to_string();
                }
            }
            1 => {
                if let Some(v) = t.get("provider").and_then(|v| v.as_str()) {
                    base.oidc.provider = v.to_string();
                }
                if let Some(v) = t.get("issuer").and_then(|v| v.as_str()) {
                    base.oidc.issuer = v.to_string();
                }
                if let Some(v) = t.get("client_id").and_then(|v| v.as_str()) {
                    base.oidc.client_id = v.to_string();
                }
                if let Some(v) = t.get("client_secret").and_then(|v| v.as_str()) {
                    base.oidc.client_secret = v.to_string();
                }
                if let Some(v) = t.get("scopes").and_then(|v| v.as_str()) {
                    base.oidc.scopes = v.to_string();
                }
                if let Some(v) = t.get("required_group").and_then(|v| v.as_str()) {
                    base.oidc.required_group = v.to_string();
                }
                if let Some(v) = t.get("redirect_path").and_then(|v| v.as_str()) {
                    base.oidc.redirect_path = v.to_string();
                }
            }
            2 => {
                if let Some(v) = t.get("url").and_then(|v| v.as_str()) {
                    base.ldap.url = v.to_string();
                }
                if let Some(v) = t.get("bind_dn_template").and_then(|v| v.as_str()) {
                    base.ldap.bind_dn_template = v.to_string();
                }
                if let Some(v) = t.get("service_bind_dn").and_then(|v| v.as_str()) {
                    base.ldap.service_bind_dn = v.to_string();
                }
                if let Some(v) = t.get("service_bind_password").and_then(|v| v.as_str()) {
                    base.ldap.service_bind_password = v.to_string();
                }
                if let Some(v) = t.get("base_dn").and_then(|v| v.as_str()) {
                    base.ldap.base_dn = v.to_string();
                }
                if let Some(v) = t.get("user_filter").and_then(|v| v.as_str()) {
                    base.ldap.user_filter = v.to_string();
                }
                if let Some(v) = t.get("scope").and_then(|v| v.as_str()) {
                    base.ldap.scope = v.to_string();
                }
                if let Some(v) = t.get("username_attr").and_then(|v| v.as_str()) {
                    base.ldap.username_attr = v.to_string();
                }
                if let Some(v) = t.get("email_attr").and_then(|v| v.as_str()) {
                    base.ldap.email_attr = v.to_string();
                }
                if let Some(v) = t.get("name_attr").and_then(|v| v.as_str()) {
                    base.ldap.name_attr = v.to_string();
                }
                if let Some(v) = t.get("groups_attr").and_then(|v| v.as_str()) {
                    base.ldap.groups_attr = v.to_string();
                }
                if let Some(v) = t.get("timeout_secs").and_then(|v| v.as_integer()) {
                    base.ldap.timeout_secs = v.clamp(1, 60) as u64;
                }
            }
            _ => {
                if let Some(v) = t.get("user_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.user_header = v.to_string();
                }
                if let Some(v) = t.get("email_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.email_header = v.to_string();
                }
                if let Some(v) = t.get("groups_header").and_then(|v| v.as_str()) {
                    base.trusted_proxy.groups_header = v.to_string();
                }
                if let Some(arr) = t.get("trusted_cidrs").and_then(|v| v.as_array()) {
                    base.trusted_proxy.trusted_cidrs = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
        }
    }
    base
}
