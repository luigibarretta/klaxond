use crate::util::{env_string, toml_get, toml_string};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

mod auth;
mod delivery;
mod routing;

pub use self::auth::{
    AuthConfig, AuthStepUpConfig, AuthToken, BasicAuthConfig, LdapConfig, OidcConfig,
    PasskeyRecord, TotpRecord, TrustedProxyConfig, WebauthnConfig,
};
pub use self::delivery::{DeliveryConfig, DeliveryPolicy, DeliveryRule, NtfyTopic, Tier};
pub use self::routing::{
    DedupSetting, InhibitionRule, NoiseControlRule, NoiseMatchField, NoiseMatchOperator,
    NoiseRuleAction, Schedule,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryConfig {
    pub backend: String,
    pub sqlite_path: PathBuf,
    pub postgres_url: String,
    pub retention: usize,
    pub default_limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyConfig {
    pub enabled: bool,
    pub allow_insecure_public_url: bool,
    pub allow_ntfy_only: bool,
    pub severities: Vec<String>,
    pub retry_seconds: u64,
    pub expire_seconds: u64,
    pub max_attempts: u32,
    pub lease_seconds: u64,
    pub telegram_after_attempts: u32,
    pub smtp_after_attempts: u32,
    pub notify_on_expiry: bool,
    pub auto_resolve: bool,
    pub exclude_sources: Vec<String>,
}

impl Default for EmergencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_insecure_public_url: false,
            allow_ntfy_only: false,
            severities: vec!["critical".to_string()],
            retry_seconds: 60,
            expire_seconds: 3_600,
            max_attempts: 50,
            lease_seconds: 60,
            telegram_after_attempts: 3,
            smtp_after_attempts: 5,
            notify_on_expiry: true,
            auto_resolve: true,
            exclude_sources: vec!["api-test".to_string()],
        }
    }
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
    pub source_urls: HashMap<String, String>,
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
    pub emergency: EmergencyConfig,
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
    pub fn source_url(&self, source: &str) -> Option<&str> {
        self.source_urls
            .get(source)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

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
        let exact = self
            .ntfy_topics
            .iter()
            .filter(|t| t.handles.iter().any(|h| h == severity))
            .cloned()
            .collect::<Vec<_>>();
        if !exact.is_empty() || severity != "resolved" {
            return exact;
        }

        // Recovery notifications are informational, but retaining the
        // distinct `resolved` severity is important for audit and metrics.
        // Reuse the info topic only when the operator has not configured a
        // dedicated resolved topic.
        self.ntfy_topics
            .iter()
            .filter(|t| t.handles.iter().any(|h| h == "info"))
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
