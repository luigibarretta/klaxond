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
    if let Some(table) = section_table(seed, "basic") {
        merge_basic_toml(&mut base, table);
    }
    if let Some(table) = section_table(seed, "oidc") {
        merge_oidc_toml(&mut base, table);
    }
    if let Some(table) = section_table(seed, "ldap") {
        merge_ldap_toml(&mut base, table);
    }
    if let Some(table) = section_table(seed, "trusted_proxy") {
        merge_trusted_proxy_toml(&mut base, table);
    }
    base
}

fn section_table<'a>(seed: &'a toml::Value, section: &str) -> Option<&'a toml::value::Table> {
    seed.get(section).and_then(|value| value.as_table())
}

fn set_string_field(table: &toml::value::Table, key: &str, target: &mut String) {
    if let Some(value) = table.get(key).and_then(|value| value.as_str()) {
        *target = value.to_string();
    }
}

fn merge_basic_toml(base: &mut AuthConfig, table: &toml::value::Table) {
    set_string_field(table, "username", &mut base.basic.username);
    set_string_field(table, "password_hash", &mut base.basic.password_hash);
    set_string_field(table, "realm", &mut base.basic.realm);
}

fn merge_oidc_toml(base: &mut AuthConfig, table: &toml::value::Table) {
    set_string_field(table, "provider", &mut base.oidc.provider);
    set_string_field(table, "issuer", &mut base.oidc.issuer);
    set_string_field(table, "client_id", &mut base.oidc.client_id);
    set_string_field(table, "client_secret", &mut base.oidc.client_secret);
    set_string_field(table, "scopes", &mut base.oidc.scopes);
    set_string_field(table, "required_group", &mut base.oidc.required_group);
    set_string_field(table, "redirect_path", &mut base.oidc.redirect_path);
}

fn merge_ldap_toml(base: &mut AuthConfig, table: &toml::value::Table) {
    set_string_field(table, "url", &mut base.ldap.url);
    set_string_field(table, "bind_dn_template", &mut base.ldap.bind_dn_template);
    set_string_field(table, "service_bind_dn", &mut base.ldap.service_bind_dn);
    set_string_field(
        table,
        "service_bind_password",
        &mut base.ldap.service_bind_password,
    );
    set_string_field(table, "base_dn", &mut base.ldap.base_dn);
    set_string_field(table, "user_filter", &mut base.ldap.user_filter);
    set_string_field(table, "scope", &mut base.ldap.scope);
    set_string_field(table, "username_attr", &mut base.ldap.username_attr);
    set_string_field(table, "email_attr", &mut base.ldap.email_attr);
    set_string_field(table, "name_attr", &mut base.ldap.name_attr);
    set_string_field(table, "groups_attr", &mut base.ldap.groups_attr);
    if let Some(value) = table
        .get("timeout_secs")
        .and_then(|value| value.as_integer())
    {
        base.ldap.timeout_secs = value.clamp(1, 60) as u64;
    }
}

fn merge_trusted_proxy_toml(base: &mut AuthConfig, table: &toml::value::Table) {
    set_string_field(table, "user_header", &mut base.trusted_proxy.user_header);
    set_string_field(table, "email_header", &mut base.trusted_proxy.email_header);
    set_string_field(
        table,
        "groups_header",
        &mut base.trusted_proxy.groups_header,
    );
    if let Some(values) = table
        .get("trusted_cidrs")
        .and_then(|value| value.as_array())
    {
        base.trusted_proxy.trusted_cidrs = values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect();
    }
}
