use super::*;
use crate::config::{NoiseControlRule, NoiseMatchField, NoiseMatchOperator, NoiseRuleAction};
use crate::delivery::tests::support::{sample_parts, test_state};

fn rule(name: &str, pattern: &str) -> NoiseControlRule {
    NoiseControlRule {
        name: name.into(),
        enabled: true,
        field: NoiseMatchField::TitleOrBody,
        label: String::new(),
        operator: NoiseMatchOperator::Contains,
        pattern: pattern.into(),
        case_sensitive: false,
        action: NoiseRuleAction::Suppress,
        cooldown_s: 7_200,
        include_critical: false,
    }
}

#[test]
fn first_matching_rule_can_suppress_or_bypass_source_default() {
    let (_tmp, state) = test_state();
    let mut cfg = state.cfg();
    let setting = cfg.dedup.get_mut("grafana").unwrap();
    setting.repeat_suppression_enabled = true;
    setting.repeat_window_s = 300;
    setting.rules = vec![
        NoiseControlRule {
            action: NoiseRuleAction::Bypass,
            ..rule("Always deliver database alerts", "database")
        },
        NoiseControlRule {
            cooldown_s: 21_600,
            ..rule("Suppress disk noise", "disk")
        },
    ];

    let mut parts = sample_parts();
    parts.title = "Database disk pressure".into();
    assert_eq!(
        select_policy(&cfg, "grafana", "warning", &parts, &HashMap::new()),
        RepeatPolicy::Disabled
    );

    parts.title = "Disk pressure".into();
    assert_eq!(
        select_policy(&cfg, "grafana", "warning", &parts, &HashMap::new()),
        RepeatPolicy::Suppress {
            window_s: 21_600,
            matched_by: "Suppress disk noise".into(),
        }
    );

    parts.title = "CPU pressure".into();
    assert_eq!(
        select_policy(&cfg, "grafana", "warning", &parts, &HashMap::new()),
        RepeatPolicy::Suppress {
            window_s: 300,
            matched_by: "source default".into(),
        }
    );
}

#[test]
fn label_regex_is_case_insensitive_and_critical_safe_by_default() {
    let (_tmp, state) = test_state();
    let mut cfg = state.cfg();
    let setting = cfg.dedup.get_mut("grafana").unwrap();
    setting.rules = vec![NoiseControlRule {
        field: NoiseMatchField::Label,
        label: "instance".into(),
        operator: NoiseMatchOperator::Regex,
        pattern: r"^NAS-\d+$".into(),
        cooldown_s: 3_600,
        ..rule("NAS alerts", "unused")
    }];
    let labels = HashMap::from([("instance".into(), "nas-01".into())]);

    assert_eq!(
        select_policy(&cfg, "grafana", "warning", &sample_parts(), &labels),
        RepeatPolicy::Suppress {
            window_s: 3_600,
            matched_by: "NAS alerts".into(),
        }
    );
    assert_eq!(
        select_policy(&cfg, "grafana", "critical", &sample_parts(), &labels),
        RepeatPolicy::Disabled
    );
}
