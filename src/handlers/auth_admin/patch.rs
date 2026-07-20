use crate::auth;
use crate::config::AuthConfig;
use serde::Deserialize;
use serde::de::{self, DeserializeOwned};
use serde_json::Value;

#[derive(Debug)]
pub(super) enum AuthConfigPatchError {
    InvalidMode,
    PasswordPolicy(String),
    HashPassword(String),
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AuthSettingsPatch {
    #[serde(default, deserialize_with = "optional_string")]
    mode: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    session_timeout_hours: Option<u64>,
    #[serde(default, deserialize_with = "optional_string")]
    session_secret: Option<String>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    basic: Option<BasicAuthPatch>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    oidc: Option<OidcPatch>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    ldap: Option<LdapPatch>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    trusted_proxy: Option<TrustedProxyPatch>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    webauthn: Option<WebauthnPatch>,
    #[serde(default, deserialize_with = "optional_object_patch")]
    step_up: Option<StepUpPatch>,
}

impl AuthSettingsPatch {
    pub(super) fn apply_to(self, auth: &mut AuthConfig) -> Result<(), AuthConfigPatchError> {
        if let Some(mode) = self.mode {
            if !matches!(
                mode.as_str(),
                "none" | "basic" | "ldap" | "oidc" | "trusted-proxy"
            ) {
                return Err(AuthConfigPatchError::InvalidMode);
            }
            auth.mode = mode;
        }
        if let Some(hours) = self.session_timeout_hours {
            auth.session_timeout_hours = hours.clamp(1, 720);
        }
        if let Some(secret) = self.session_secret
            && secret != "***SET***"
        {
            auth.session_secret = secret;
        }
        if let Some(patch) = self.basic {
            patch.apply_to(auth)?;
        }
        if let Some(patch) = self.oidc {
            patch.apply_to(auth);
        }
        if let Some(patch) = self.ldap {
            patch.apply_to(auth);
        }
        if let Some(patch) = self.trusted_proxy {
            patch.apply_to(auth);
        }
        if let Some(patch) = self.webauthn {
            patch.apply_to(auth);
        }
        if let Some(patch) = self.step_up {
            patch.apply_to(auth);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
struct BasicAuthPatch {
    #[serde(default, deserialize_with = "optional_string")]
    username: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    realm: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    password: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    password_hash: Option<String>,
}

impl BasicAuthPatch {
    fn apply_to(self, auth: &mut AuthConfig) -> Result<(), AuthConfigPatchError> {
        if let Some(username) = self.username {
            auth.basic.username = username;
        }
        if let Some(realm) = self.realm {
            auth.basic.realm = realm;
        }
        if let Some(password) = self.password.filter(|password| !password.is_empty()) {
            if let Err(error) =
                auth::validate_password_policy(&password, Some(&auth.basic.username))
            {
                return Err(AuthConfigPatchError::PasswordPolicy(error.message()));
            }
            auth.basic.password_hash = auth::hash_password(&password)
                .map_err(|err| AuthConfigPatchError::HashPassword(err.to_string()))?;
        } else if let Some(hash) = self
            .password_hash
            .filter(|hash| hash != "***SET***" && !hash.is_empty())
        {
            auth.basic.password_hash = hash;
        }
        Ok(())
    }
}

#[derive(Default, Deserialize)]
struct OidcPatch {
    #[serde(default, deserialize_with = "optional_string")]
    provider: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    issuer: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    client_id: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    client_secret: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    scopes: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    required_group: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    redirect_path: Option<String>,
}

impl std::fmt::Debug for OidcPatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcPatch")
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .field("required_group", &self.required_group)
            .field("redirect_path", &self.redirect_path)
            .finish()
    }
}

impl OidcPatch {
    fn apply_to(self, auth: &mut AuthConfig) {
        apply_string(self.provider, &mut auth.oidc.provider);
        apply_string(self.issuer, &mut auth.oidc.issuer);
        apply_string(self.client_id, &mut auth.oidc.client_id);
        apply_string(self.scopes, &mut auth.oidc.scopes);
        apply_string(self.required_group, &mut auth.oidc.required_group);
        apply_string(self.redirect_path, &mut auth.oidc.redirect_path);
        if let Some(secret) = self
            .client_secret
            .filter(|secret| !secret.is_empty() && secret != "***SET***")
        {
            auth.oidc.client_secret = secret;
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct LdapPatch {
    #[serde(default, deserialize_with = "optional_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    bind_dn_template: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    service_bind_dn: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    service_bind_password: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    base_dn: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    user_filter: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    username_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    email_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    name_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    groups_attr: Option<String>,
    #[serde(default, deserialize_with = "optional_u64")]
    timeout_secs: Option<u64>,
}

impl LdapPatch {
    fn apply_to(self, auth: &mut AuthConfig) {
        apply_trimmed_string(self.url, &mut auth.ldap.url);
        apply_trimmed_string(self.bind_dn_template, &mut auth.ldap.bind_dn_template);
        apply_trimmed_string(self.service_bind_dn, &mut auth.ldap.service_bind_dn);
        apply_trimmed_string(self.base_dn, &mut auth.ldap.base_dn);
        apply_trimmed_string(self.user_filter, &mut auth.ldap.user_filter);
        apply_trimmed_string(self.scope, &mut auth.ldap.scope);
        apply_trimmed_string(self.username_attr, &mut auth.ldap.username_attr);
        apply_trimmed_string(self.email_attr, &mut auth.ldap.email_attr);
        apply_trimmed_string(self.name_attr, &mut auth.ldap.name_attr);
        apply_trimmed_string(self.groups_attr, &mut auth.ldap.groups_attr);
        if let Some(password) = self
            .service_bind_password
            .filter(|password| !password.is_empty() && password != "***SET***")
        {
            auth.ldap.service_bind_password = password;
        }
        if let Some(timeout_secs) = self.timeout_secs {
            auth.ldap.timeout_secs = timeout_secs.clamp(1, 60);
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct TrustedProxyPatch {
    #[serde(default, deserialize_with = "optional_string")]
    user_header: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    email_header: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    groups_header: Option<String>,
    #[serde(default, deserialize_with = "optional_string_vec")]
    trusted_cidrs: Option<Vec<String>>,
}

impl TrustedProxyPatch {
    fn apply_to(self, auth: &mut AuthConfig) {
        apply_string(self.user_header, &mut auth.trusted_proxy.user_header);
        apply_string(self.email_header, &mut auth.trusted_proxy.email_header);
        apply_string(self.groups_header, &mut auth.trusted_proxy.groups_header);
        if let Some(trusted_cidrs) = self.trusted_cidrs {
            auth.trusted_proxy.trusted_cidrs = trusted_cidrs;
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct WebauthnPatch {
    #[serde(default, deserialize_with = "optional_bool")]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "optional_string")]
    rp_id: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    origin: Option<String>,
}

impl WebauthnPatch {
    fn apply_to(self, auth: &mut AuthConfig) {
        if let Some(enabled) = self.enabled {
            auth.webauthn.enabled = enabled;
        }
        if let Some(rp_id) = self.rp_id {
            auth.webauthn.rp_id = rp_id.trim().to_string();
        }
        if let Some(origin) = self.origin {
            auth.webauthn.origin = origin.trim().trim_end_matches('/').to_string();
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct StepUpPatch {
    #[serde(default, deserialize_with = "optional_bool")]
    required_after_primary: Option<bool>,
    #[serde(default, deserialize_with = "optional_string")]
    factor: Option<String>,
    #[serde(default, deserialize_with = "optional_bool")]
    oidc_requires_passkey: Option<bool>,
}

impl StepUpPatch {
    fn apply_to(self, auth: &mut AuthConfig) {
        if let Some(required) = self.required_after_primary {
            auth.step_up.required_after_primary = required;
        }
        if let Some(factor) = self.factor {
            auth.step_up.factor = factor.trim().to_string();
        }
        if let Some(legacy) = self.oidc_requires_passkey {
            auth.step_up.oidc_requires_passkey = legacy;
        }
        auth.step_up.normalize();
    }
}

fn apply_string(value: Option<String>, slot: &mut String) {
    if let Some(value) = value {
        *slot = value;
    }
}

fn apply_trimmed_string(value: Option<String>, slot: &mut String) {
    if let Some(value) = value {
        *slot = value.trim().to_string();
    }
}

fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

fn optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    })
}

fn optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Bool(value)) => Some(value),
        _ => None,
    })
}

fn optional_string_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Array(values)) => Some(
            values
                .into_iter()
                .filter_map(|value| match value {
                    Value::String(value) => Some(value),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    })
}

fn optional_object_patch<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: DeserializeOwned,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(value @ Value::Object(_)) => serde_json::from_value(value)
            .map(Some)
            .map_err(de::Error::custom),
        _ => Ok(None),
    }
}
