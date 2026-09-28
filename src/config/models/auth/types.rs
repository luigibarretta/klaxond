use super::defaults::{default_ldap_scope_name, default_step_up_factor, default_true, is_false};
use auth_modules::ldap::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr,
    default_ldap_timeout_secs, default_ldap_user_filter, default_ldap_username_attr,
};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub mode: String,
    #[serde(default)]
    pub session_secret: String,
    pub session_timeout_hours: u64,
    pub basic: BasicAuthConfig,
    pub oidc: OidcConfig,
    #[serde(default)]
    pub ldap: LdapConfig,
    pub trusted_proxy: TrustedProxyConfig,
    #[serde(default)]
    pub webauthn: WebauthnConfig,
    #[serde(default)]
    pub step_up: AuthStepUpConfig,
    #[serde(default)]
    pub api_keys: Vec<AuthToken>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyRecord>,
    #[serde(default)]
    pub totp_factors: Vec<TotpRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password_hash: String,
    pub realm: String,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_last_counter: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OidcConfig {
    pub provider: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub required_group: String,
    pub redirect_path: String,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcConfig")
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("required_group", &self.required_group)
            .field("redirect_path", &self.redirect_path)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    #[serde(default)]
    pub bind_dn_template: String,
    #[serde(default)]
    pub service_bind_dn: String,
    #[serde(default)]
    pub service_bind_password: String,
    #[serde(default)]
    pub base_dn: String,
    #[serde(default = "default_ldap_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_ldap_scope_name")]
    pub scope: String,
    #[serde(default = "default_ldap_username_attr")]
    pub username_attr: String,
    #[serde(default = "default_ldap_email_attr")]
    pub email_attr: String,
    #[serde(default = "default_ldap_name_attr")]
    pub name_attr: String,
    #[serde(default = "default_ldap_groups_attr")]
    pub groups_attr: String,
    #[serde(default = "default_ldap_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedProxyConfig {
    pub user_header: String,
    pub email_header: String,
    pub groups_header: String,
    pub trusted_cidrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnConfig {
    pub enabled: bool,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthStepUpConfig {
    #[serde(default)]
    pub required_after_primary: bool,
    #[serde(default = "default_step_up_factor")]
    pub factor: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub oidc_requires_passkey: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub prefix: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: String,
    pub name: String,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub user_uuid: String,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    pub credential: Passkey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpRecord {
    pub id: String,
    pub name: String,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub secret: String,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_counter: Option<u64>,
}
