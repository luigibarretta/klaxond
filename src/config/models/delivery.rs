use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

impl DeliveryConfig {
    pub fn validate(&self) -> Result<(), String> {
        let policy_names = self.validate_policies()?;
        if !policy_names.contains(self.default_policy.as_str()) {
            return Err(format!(
                "unknown default delivery policy '{}'",
                self.default_policy
            ));
        }
        self.validate_rules(&policy_names)
    }

    fn validate_policies(&self) -> Result<HashSet<&str>, String> {
        let mut names = HashSet::from(["cascade"]);
        for policy in &self.policies {
            if policy.name.trim().is_empty() || policy.name.len() > 64 {
                return Err("delivery policy names must contain 1 to 64 characters".into());
            }
            if !names.insert(policy.name.as_str()) {
                return Err(format!(
                    "duplicate or reserved delivery policy '{}'",
                    policy.name
                ));
            }
            if !matches!(policy.mode.as_str(), "cascade" | "broadcast") {
                return Err(format!(
                    "delivery policy '{}' has an invalid mode",
                    policy.name
                ));
            }
            if policy.tiers.is_empty() {
                return Err(format!(
                    "delivery policy '{}' needs at least one tier",
                    policy.name
                ));
            }
            for tier in &policy.tiers {
                if !matches!(tier.name.as_str(), "ntfy" | "telegram" | "smtp") {
                    return Err(format!(
                        "delivery policy '{}' has an unknown tier",
                        policy.name
                    ));
                }
                if !(1..=60).contains(&tier.timeout_seconds) {
                    return Err(format!(
                        "delivery policy '{}' tier '{}' timeout must be between 1 and 60 seconds",
                        policy.name, tier.name
                    ));
                }
            }
        }
        Ok(names)
    }

    fn validate_rules(&self, policy_names: &HashSet<&str>) -> Result<(), String> {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.r#match.is_empty() {
                return Err(format!(
                    "delivery rule {} needs at least one match",
                    index + 1
                ));
            }
            if !policy_names.contains(rule.policy.as_str()) {
                return Err(format!(
                    "delivery rule {} references unknown policy '{}'",
                    index + 1,
                    rule.policy
                ));
            }
            validate_rule_match(index, rule)?;
        }
        Ok(())
    }
}

fn validate_rule_match(index: usize, rule: &DeliveryRule) -> Result<(), String> {
    for (label, expected) in &rule.r#match {
        if label.trim().is_empty() || expected.is_empty() {
            return Err(format!(
                "delivery rule {} has an empty label or value",
                index + 1
            ));
        }
        if let Some(pattern) = expected.strip_prefix("re:") {
            regex::Regex::new(pattern).map_err(|error| {
                format!(
                    "delivery rule {} label '{}' has invalid regex: {error}",
                    index + 1,
                    label
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_rule_regex() {
        let config = DeliveryConfig {
            rules: vec![DeliveryRule {
                r#match: HashMap::from([("host".into(), "re:[".into())]),
                policy: "cascade".into(),
            }],
            ..DeliveryConfig::default()
        };

        let error = config.validate().expect_err("invalid regex must fail");
        assert!(error.contains("rule 1"));
        assert!(error.contains("invalid regex"));
    }

    #[test]
    fn accepts_rust_regex_flags_not_supported_by_javascript() {
        let config = DeliveryConfig {
            rules: vec![DeliveryRule {
                r#match: HashMap::from([("host".into(), "re:(?i)^prod-".into())]),
                policy: "cascade".into(),
            }],
            ..DeliveryConfig::default()
        };

        assert!(config.validate().is_ok());
    }
}
