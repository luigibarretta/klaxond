use crate::config::{
    NoiseControlRule, NoiseMatchField, NoiseMatchOperator, NoiseRuleAction, RuntimeConfig,
};
use crate::parsers::Parts;
use regex::RegexBuilder;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RepeatPolicy {
    Disabled,
    Suppress { window_s: u64, matched_by: String },
}

pub(super) fn select_policy(
    cfg: &RuntimeConfig,
    source: &str,
    severity: &str,
    parts: &Parts,
    labels: &HashMap<String, String>,
) -> RepeatPolicy {
    let Some(setting) = cfg.dedup.get(source) else {
        return RepeatPolicy::Disabled;
    };

    for rule in setting.rules.iter().filter(|rule| rule.enabled) {
        if !rule_matches(rule, parts, labels) {
            continue;
        }
        return match rule.action {
            NoiseRuleAction::Bypass => RepeatPolicy::Disabled,
            NoiseRuleAction::Suppress if severity == "critical" && !rule.include_critical => {
                RepeatPolicy::Disabled
            }
            NoiseRuleAction::Suppress => RepeatPolicy::Suppress {
                window_s: rule.cooldown_s,
                matched_by: rule.name.clone(),
            },
        };
    }

    if setting.repeat_suppression_enabled
        && (severity != "critical" || setting.repeat_override_critical)
    {
        RepeatPolicy::Suppress {
            window_s: setting.repeat_window_s,
            matched_by: "source default".into(),
        }
    } else {
        RepeatPolicy::Disabled
    }
}

fn rule_matches(rule: &NoiseControlRule, parts: &Parts, labels: &HashMap<String, String>) -> bool {
    match rule.field {
        NoiseMatchField::TitleOrBody => {
            value_matches(rule, &parts.title) || value_matches(rule, &parts.body)
        }
        NoiseMatchField::Title => value_matches(rule, &parts.title),
        NoiseMatchField::Body => value_matches(rule, &parts.body),
        NoiseMatchField::Alertname => value_matches(rule, &parts.alertname),
        NoiseMatchField::Label => labels
            .get(&rule.label)
            .is_some_and(|value| value_matches(rule, value)),
    }
}

fn value_matches(rule: &NoiseControlRule, value: &str) -> bool {
    match rule.operator {
        NoiseMatchOperator::Exact if rule.case_sensitive => value == rule.pattern,
        NoiseMatchOperator::Contains if rule.case_sensitive => value.contains(&rule.pattern),
        NoiseMatchOperator::Exact => value.to_lowercase() == rule.pattern.to_lowercase(),
        NoiseMatchOperator::Contains => value.to_lowercase().contains(&rule.pattern.to_lowercase()),
        NoiseMatchOperator::Regex => RegexBuilder::new(&rule.pattern)
            .case_insensitive(!rule.case_sensitive)
            .build()
            .is_ok_and(|regex| regex.is_match(value)),
    }
}

#[cfg(test)]
mod tests;
