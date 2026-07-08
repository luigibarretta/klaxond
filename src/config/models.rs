use crate::util::{env_string, toml_get, toml_string};
use auth_modules::ldap::{
    default_ldap_email_attr, default_ldap_groups_attr, default_ldap_name_attr, default_ldap_scope,
    default_ldap_timeout_secs, default_ldap_user_filter, default_ldap_username_attr,
    ldap_scope_from_name, ldap_scope_name,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use webauthn_rs::prelude::Passkey;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NtfyTopic {
    pub name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub handles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tier {
    pub name: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    5
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryPolicy {
    pub name: String,
    #[serde(default = "cascade_mode")]
    pub mode: String,
    #[serde(default)]
    pub tiers: Vec<Tier>,
}

fn cascade_mode() -> String {
    "cascade".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryRule {
    #[serde(default)]
    pub r#match: HashMap<String, String>,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryConfig {
    pub default_policy: String,
    pub policies: Vec<DeliveryPolicy>,
    pub rules: Vec<DeliveryRule>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            default_policy: "cascade".to_string(),
            policies: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryConfig {
    pub backend: String,
    pub sqlite_path: PathBuf,
    pub postgres_url: String,
    pub retention: usize,
    pub default_limit: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InhibitionRule {
    pub source: String,
    #[serde(default)]
    pub match_by: Option<String>,
    #[serde(default)]
    pub match_label: Option<String>,
    #[serde(default)]
    pub match_regex: Option<String>,
    #[serde(default)]
    pub match_all: bool,
    #[serde(default)]
    pub applies_to: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    900
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DedupSetting {
    pub enabled: bool,
    pub window_s: u64,
    pub strategy: String,
    pub override_critical: bool,
}

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
    pub api_keys: Vec<AuthToken>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyRecord>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub provider: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub required_group: String,
    pub redirect_path: String,
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

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rp_id: String::new(),
            origin: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_ldap_scope_name() -> String {
    ldap_scope_name(default_ldap_scope()).to_string()
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            bind_dn_template: String::new(),
            service_bind_dn: String::new(),
            service_bind_password: String::new(),
            base_dn: String::new(),
            user_filter: default_ldap_user_filter(),
            scope: default_ldap_scope_name(),
            username_attr: default_ldap_username_attr(),
            email_attr: default_ldap_email_attr(),
            name_attr: default_ldap_name_attr(),
            groups_attr: default_ldap_groups_attr(),
            timeout_secs: default_ldap_timeout_secs(),
        }
    }
}

impl LdapConfig {
    pub fn to_auth_modules_config(&self) -> Option<auth_modules::ldap::LdapAuthConfig> {
        let url = self.url.trim();
        if url.is_empty() {
            return None;
        }
        let bind_dn_template = clean_optional_string(&self.bind_dn_template);
        let service_bind_dn = clean_optional_string(&self.service_bind_dn);
        let service_bind_password = clean_optional_string(&self.service_bind_password);
        if bind_dn_template.is_none()
            && (service_bind_dn.is_none() || service_bind_password.is_none())
        {
            return None;
        }
        Some(auth_modules::ldap::LdapAuthConfig {
            url: url.to_string(),
            bind_dn_template,
            service_bind_dn,
            service_bind_password,
            base_dn: clean_optional_string(&self.base_dn),
            user_filter: clean_optional_string(&self.user_filter)
                .unwrap_or_else(default_ldap_user_filter),
            scope: ldap_scope_from_name(&self.scope).unwrap_or_else(default_ldap_scope),
            username_attr: clean_optional_string(&self.username_attr)
                .unwrap_or_else(default_ldap_username_attr),
            email_attr: clean_optional_string(&self.email_attr)
                .unwrap_or_else(default_ldap_email_attr),
            name_attr: clean_optional_string(&self.name_attr)
                .unwrap_or_else(default_ldap_name_attr),
            groups_attr: clean_optional_string(&self.groups_attr)
                .unwrap_or_else(default_ldap_groups_attr),
            timeout_secs: self.timeout_secs.clamp(1, 60),
        })
    }
}

fn clean_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty() && trimmed != "***SET***").then(|| trimmed.to_string())
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "none".to_string(),
            session_secret: String::new(),
            session_timeout_hours: 8,
            basic: BasicAuthConfig {
                username: String::new(),
                password_hash: String::new(),
                realm: "klaxond".to_string(),
                totp_enabled: false,
                totp_secret: String::new(),
            },
            oidc: OidcConfig {
                provider: "authentik".to_string(),
                issuer: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                scopes: "openid profile email".to_string(),
                required_group: String::new(),
                redirect_path: "/api/auth/callback".to_string(),
            },
            ldap: LdapConfig::default(),
            trusted_proxy: TrustedProxyConfig {
                user_header: "X-Forwarded-User".to_string(),
                email_header: "X-Forwarded-Email".to_string(),
                groups_header: "X-Forwarded-Groups".to_string(),
                trusted_cidrs: vec![
                    "127.0.0.1/32".to_string(),
                    "192.168.0.0/16".to_string(),
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                ],
            },
            webauthn: WebauthnConfig::default(),
            api_keys: Vec::new(),
            passkeys: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub name: String,
    pub cron: String,
    pub duration_minutes: u64,
    #[serde(default)]
    pub r#match: HashMap<String, String>,
    #[serde(default)]
    pub applies_to: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub toml: toml::Value,
    pub port: u16,
    pub ntfy_url: String,
    pub ntfy_topics: Vec<NtfyTopic>,
    pub priorities: HashMap<String, String>,
    pub icons: HashMap<String, String>,
    pub tag_prefixes: HashMap<String, String>,
    pub fallback_runbooks: HashMap<String, String>,
    pub component_dashboards: HashMap<String, [String; 2]>,
    pub component_image: HashMap<String, (String, Option<u64>)>,
    pub cascade_default: bool,
    pub tiers: Vec<Tier>,
    pub delivery: DeliveryConfig,
    pub inhibition_rules: Vec<InhibitionRule>,
    pub dedup: HashMap<String, DedupSetting>,
    pub auth: AuthConfig,
    pub schedules: Vec<Schedule>,
    pub history: HistoryConfig,
    pub tg_chat: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_from: String,
    pub smtp_to: String,
    pub tg_token: String,
    pub telegram_api_base: String,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub grafana_base: String,
    pub grafana_render_base: String,
    pub grafana_render_token: String,
    pub render_image_ttl: u64,
    pub public_url: String,
    pub ack_default_ttl: u64,
    pub beszel_db: PathBuf,
}

impl RuntimeConfig {
    pub(super) fn with_channels(mut self) -> Self {
        let toml = self.toml.clone();
        self.tg_chat = env_string("TELEGRAM_CHAT_ID")
            .if_empty_else(|| toml_string(toml_get(&toml, &["telegram", "chat_id"])));
        self.smtp_host = env_string("SMTP_HOST")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "host"])));
        self.smtp_from = env_string("SMTP_FROM")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "from_addr"])))
            .if_empty_else(|| self.smtp_user.clone());
        self.smtp_to = env_string("SMTP_TO")
            .if_empty_else(|| toml_string(toml_get(&toml, &["smtp", "to_addr"])));
        self
    }

    pub fn known_severities(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .ntfy_topics
            .iter()
            .flat_map(|t| t.handles.iter().cloned())
            .collect();
        out.push("resolved".to_string());
        out.sort();
        out.dedup();
        out
    }

    pub fn handles_severity(&self, severity: &str) -> bool {
        severity == "resolved"
            || self
                .ntfy_topics
                .iter()
                .any(|t| t.handles.iter().any(|h| h == severity))
    }

    pub fn topics_for(&self, severity: &str) -> Vec<NtfyTopic> {
        self.ntfy_topics
            .iter()
            .filter(|t| t.handles.iter().any(|h| h == severity))
            .cloned()
            .collect()
    }

    pub fn icon(&self, severity: &str) -> String {
        self.icons
            .get(severity)
            .or_else(|| self.icons.get("info"))
            .cloned()
            .unwrap_or_else(|| "ℹ️".to_string())
    }

    pub fn tag_prefix(&self, severity: &str) -> String {
        self.tag_prefixes
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "bell".to_string())
    }

    pub fn priority(&self, severity: &str) -> String {
        self.priorities
            .get(severity)
            .cloned()
            .unwrap_or_else(|| "default".to_string())
    }
}

trait EmptyExt {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String;
}

impl EmptyExt for String {
    fn if_empty_else<F: FnOnce() -> String>(self, f: F) -> String {
        if self.is_empty() { f() } else { self }
    }
}
