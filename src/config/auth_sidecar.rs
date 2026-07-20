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
        write_auth(paths, &out)?;
    }
    if normalize_auth_config(&mut out) {
        save_auth(paths, &out)?;
    }
    apply_auth_env_overrides(&mut out)?;
    Ok(out)
}

fn apply_auth_env_overrides(auth: &mut AuthConfig) -> Result<()> {
    if let Ok(secret) = std::env::var("AUTH_OIDC_CLIENT_SECRET")
        && env_value_is_set(&secret)
    {
        auth.oidc.client_secret = secret;
    }
    if let Ok(hash) = std::env::var("AUTH_BASIC_PASSWORD_HASH")
        && env_value_is_set(&hash)
    {
        auth.basic.password_hash = hash;
    }
    if let Ok(raw) = std::env::var("AUTH_TRUSTED_PROXY_CIDRS")
        && !raw.trim().is_empty()
    {
        let cidrs = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<ipnet::IpNet>()
                    .map(|network| network.to_string())
                    .map_err(|err| anyhow::anyhow!("invalid AUTH_TRUSTED_PROXY_CIDRS: {err}"))
            })
            .collect::<Result<Vec<_>>>()?;
        if cidrs.is_empty() {
            anyhow::bail!("AUTH_TRUSTED_PROXY_CIDRS must contain at least one CIDR");
        }
        auth.trusted_proxy.trusted_cidrs = cidrs;
    }
    Ok(())
}

pub fn save_auth(paths: &Paths, auth: &AuthConfig) -> Result<()> {
    write_auth(paths, &auth_for_persistence(paths, auth)?)
}

fn write_auth(paths: &Paths, auth: &AuthConfig) -> Result<()> {
    atomic_write_json(&paths.auth_config, auth)
}

fn auth_for_persistence(paths: &Paths, auth: &AuthConfig) -> Result<AuthConfig> {
    let mut persisted = auth.clone();
    let existing = if paths.auth_config.exists() {
        Some(serde_json::from_slice::<AuthConfig>(&fs::read(
            &paths.auth_config,
        )?)?)
    } else {
        None
    };
    if env_override_is_set("AUTH_OIDC_CLIENT_SECRET") {
        persisted.oidc.client_secret = existing
            .as_ref()
            .map(|auth| auth.oidc.client_secret.clone())
            .unwrap_or_default();
    }
    if env_override_is_set("AUTH_BASIC_PASSWORD_HASH") {
        persisted.basic.password_hash = existing
            .as_ref()
            .map(|auth| auth.basic.password_hash.clone())
            .unwrap_or_default();
    }
    if env_override_is_set("AUTH_TRUSTED_PROXY_CIDRS") {
        persisted.trusted_proxy.trusted_cidrs = existing
            .as_ref()
            .map(|auth| auth.trusted_proxy.trusted_cidrs.clone())
            .unwrap_or_else(|| AuthConfig::default().trusted_proxy.trusted_cidrs);
    }
    Ok(persisted)
}

fn env_override_is_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| env_value_is_set(&value))
}

fn env_value_is_set(value: &str) -> bool {
    !value.trim().is_empty()
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
    base.step_up = raw.step_up;
    base.api_keys = raw.api_keys;
    base.passkeys = raw.passkeys;
    base.totp_factors = raw.totp_factors;
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
    if auth.step_up.normalize() {
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
    if let Some(table) = section_table(seed, "step_up") {
        merge_step_up_toml(&mut base, table);
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

fn merge_step_up_toml(base: &mut AuthConfig, table: &toml::value::Table) {
    if let Some(value) = table
        .get("required_after_primary")
        .and_then(|value| value.as_bool())
    {
        base.step_up.required_after_primary = value;
    }
    set_string_field(table, "factor", &mut base.step_up.factor);
    if let Some(value) = table
        .get("oidc_requires_passkey")
        .and_then(|value| value.as_bool())
    {
        base.step_up.oidc_requires_passkey = value;
    }
    base.step_up.normalize();
}
