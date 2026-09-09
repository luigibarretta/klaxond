use super::{DedupSetting, INGEST_SOURCES};
use std::collections::HashMap;

pub const MAX_CUSTOM_INGEST_SOURCES: usize = 32;

pub fn custom_ingest_sources(toml: &toml::Value) -> HashMap<String, String> {
    let mut sources: HashMap<String, String> = toml
        .get("ingest")
        .and_then(|value| value.get("custom_sources"))
        .and_then(toml::Value::as_table)
        .map(|sources| {
            sources
                .iter()
                .filter_map(|(slug, value)| {
                    let display_name = value.as_str()?.trim();
                    valid_custom_source(slug, display_name)
                        .then(|| (slug.clone(), display_name.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    sources.extend(environment_custom_ingest_sources());
    sources
}

pub fn environment_custom_ingest_sources() -> HashMap<String, String> {
    environment_json_map("KLAXOND_CUSTOM_INGEST_SOURCES")
        .into_iter()
        .filter_map(|(slug, display_name)| {
            let display_name = display_name.trim();
            valid_custom_source(&slug, display_name).then(|| (slug, display_name.to_string()))
        })
        .collect()
}

pub fn environment_custom_ingest_secrets() -> HashMap<String, String> {
    environment_json_map("KLAXOND_CUSTOM_INGEST_SECRETS")
        .into_iter()
        .filter(|(slug, secret)| valid_ingest_source_slug(slug) && !secret.trim().is_empty())
        .collect()
}

fn environment_json_map(name: &str) -> HashMap<String, String> {
    let Ok(value) = std::env::var(name) else {
        return HashMap::new();
    };
    if value.trim().is_empty() {
        return HashMap::new();
    }
    serde_json::from_str::<HashMap<String, String>>(&value).unwrap_or_else(|error| {
        tracing::warn!(%error, variable = name, "ignoring invalid JSON object");
        HashMap::new()
    })
}

pub fn valid_ingest_source_slug(source: &str) -> bool {
    let len = source.len();
    (2..=40).contains(&len)
        && source.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-' && index > 0 && index + 1 < len)
        })
        && !source.contains("--")
}

pub fn source_is_builtin(source: &str) -> bool {
    INGEST_SOURCES.contains(&source)
}

fn valid_custom_source(source: &str, display_name: &str) -> bool {
    valid_ingest_source_slug(source)
        && !source_is_builtin(source)
        && !display_name.is_empty()
        && display_name.chars().count() <= 64
}

pub fn default_dedup_setting() -> DedupSetting {
    DedupSetting {
        enabled: false,
        window_s: 90,
        strategy: "key".into(),
        override_critical: false,
        repeat_suppression_enabled: false,
        repeat_window_s: 7_200,
        repeat_override_critical: false,
        rules: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{custom_ingest_sources, valid_ingest_source_slug};

    #[test]
    fn custom_source_slugs_are_url_and_environment_safe() {
        for valid in ["home-assistant", "service2", "my-source"] {
            assert!(
                valid_ingest_source_slug(valid),
                "expected {valid} to be valid"
            );
        }
        for invalid in [
            "A",
            "UPPERCASE",
            "-leading",
            "trailing-",
            "two--hyphens",
            "has space",
            "under_score",
        ] {
            assert!(
                !valid_ingest_source_slug(invalid),
                "expected {invalid} to be invalid"
            );
        }
    }

    #[test]
    fn custom_sources_load_from_toml() {
        let config: toml::Value = toml::from_str(
            r#"
            [ingest.custom_sources]
            "home-assistant" = "Home Assistant"
            grafana = "Not a custom source"
            "bad source" = "Ignored"
        "#,
        )
        .unwrap();
        let sources = custom_ingest_sources(&config);
        assert_eq!(
            sources.get("home-assistant").map(String::as_str),
            Some("Home Assistant")
        );
        assert!(!sources.contains_key("grafana"));
        assert!(!sources.contains_key("bad source"));
    }
}
