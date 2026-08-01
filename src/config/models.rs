use crate::util::{env_string, toml_get, toml_string};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

mod auth;

pub use self::auth::{
    AuthConfig, AuthStepUpConfig, AuthToken, BasicAuthConfig, LdapConfig, OidcConfig,
    PasskeyRecord, TotpRecord, TrustedProxyConfig, WebauthnConfig,
};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupSetting {
    pub enabled: bool,
    pub window_s: u64,
    pub strategy: String,
    pub override_critical: bool,
    #[serde(default)]
    pub repeat_suppression_enabled: bool,
    #[serde(default = "default_repeat_window")]
    pub repeat_window_s: u64,
    #[serde(default)]
    pub repeat_override_critical: bool,
    #[serde(default)]
    pub rules: Vec<NoiseControlRule>,
}

fn default_repeat_window() -> u64 {
    7_200
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseMatchField {
    #[default]
    TitleOrBody,
    Title,
    Body,
    Alertname,
    Label,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseMatchOperator {
    Exact,
    #[default]
    Contains,
    Regex,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseRuleAction {
    #[default]
    Suppress,
    Bypass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseControlRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub field: NoiseMatchField,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub operator: NoiseMatchOperator,
    pub pattern: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub action: NoiseRuleAction,
    #[serde(default = "default_repeat_window")]
    pub cooldown_s: u64,
    #[serde(default)]
    pub include_critical: bool,
}

fn default_true() -> bool {
    true
}

impl NoiseControlRule {
    pub fn normalize(&mut self) {
        self.name = self.name.trim().to_string();
        self.label = self.label.trim().to_string();
        self.pattern = self.pattern.trim().to_string();
        self.cooldown_s = self.cooldown_s.clamp(60, 604_800);
        if self.field != NoiseMatchField::Label {
            self.label.clear();
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("rule name is required".into());
        }
        if self.name.chars().count() > 80 {
            return Err("rule name must be at most 80 characters".into());
        }
        if self.pattern.is_empty() {
            return Err("match value is required".into());
        }
        if self.pattern.chars().count() > 512 {
            return Err("match value must be at most 512 characters".into());
        }
        if self.field == NoiseMatchField::Label {
            if self.label.is_empty() {
                return Err("label name is required when matching a label".into());
            }
            if self.label.chars().count() > 128 {
                return Err("label name must be at most 128 characters".into());
            }
        }
        if self.operator == NoiseMatchOperator::Regex {
            RegexBuilder::new(&self.pattern)
                .case_insensitive(!self.case_sensitive)
                .build()
                .map_err(|error| format!("invalid regex: {error}"))?;
        }
        Ok(())
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
