use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
