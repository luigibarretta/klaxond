use crate::config::{EmergencyConfig, emergency_timeline, select_emergency_profile};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) fn configured_severities(cfg: &crate::config::RuntimeConfig) -> Vec<String> {
    let mut severities = cfg.known_severities();
    for profile in &cfg.emergency.profiles {
        severities.extend(
            profile
                .severities
                .iter()
                .filter(|value| !value.starts_with("re:"))
                .cloned(),
        );
    }
    severities.retain(|severity| severity != "resolved");
    severities.sort();
    severities.dedup();
    severities
}

pub(super) fn profile_diagnostics(
    config: &EmergencyConfig,
    severities: &[String],
    sources: &[String],
) -> Value {
    json!({
        "shadowed_profiles": shadowed_profiles(config),
        "unrouted_severities": unrouted_severities(config, severities, sources),
        "equal_priorities": duplicate_priorities(config),
        "timelines": timelines(config),
    })
}

fn shadowed_profiles(config: &EmergencyConfig) -> Vec<Value> {
    config
        .profiles
        .iter()
        .enumerate()
        .filter_map(|(index, profile)| {
            if !profile.enabled {
                return None;
            }
            config
                .profiles
                .iter()
                .enumerate()
                .filter(|(candidate_index, candidate)| {
                    *candidate_index != index
                        && candidate.enabled
                        && (candidate.priority > profile.priority
                            || (candidate.priority == profile.priority && *candidate_index < index))
                })
                .find(|(_, candidate)| {
                    candidate.severities == profile.severities
                        && candidate.sources == profile.sources
                        && candidate.label_match == profile.label_match
                })
                .map(|(_, winner)| json!({"profile": profile.id, "shadowed_by": winner.id}))
        })
        .collect()
}

fn unrouted_severities(
    config: &EmergencyConfig,
    severities: &[String],
    sources: &[String],
) -> Vec<String> {
    let mut routing_config = config.clone();
    routing_config.enabled = true;
    severities
        .iter()
        .filter(|severity| {
            sources.iter().all(|source| {
                select_emergency_profile(&routing_config, severity, source, "", &HashMap::new())
                    .selected
                    .is_none()
            })
        })
        .cloned()
        .collect()
}

fn timelines(config: &EmergencyConfig) -> Value {
    let timelines = config
        .profiles
        .iter()
        .map(|profile| (profile.id.clone(), emergency_timeline(profile)))
        .collect::<BTreeMap<_, _>>();
    json!(timelines)
}

fn duplicate_priorities(config: &EmergencyConfig) -> HashSet<i32> {
    let priorities = config
        .profiles
        .iter()
        .map(|profile| profile.priority)
        .collect::<Vec<_>>();
    priorities
        .iter()
        .filter(|priority| {
            priorities
                .iter()
                .filter(|value| *value == *priority)
                .count()
                > 1
        })
        .copied()
        .collect()
}
