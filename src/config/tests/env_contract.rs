use super::*;
use std::fs;
use std::path::PathBuf;

mod runtime;

const COMPOSE_FILE_CONFIG_EQUIVALENTS: &[(&str, &str)] = &[
    ("NTFY_URL", "TOML [ntfy].url"),
    (
        "NTFY_TOKEN_INFO",
        "TOML/JSON ntfy topic token for handles=[info]",
    ),
    (
        "NTFY_TOKEN_WARN",
        "TOML/JSON ntfy topic token for handles=[warning]",
    ),
    (
        "NTFY_TOKEN_CRIT",
        "TOML/JSON ntfy topic token for handles=[critical]",
    ),
    ("TOPIC_INFO", "TOML/JSON ntfy topic name for handles=[info]"),
    (
        "TOPIC_WARN",
        "TOML/JSON ntfy topic name for handles=[warning]",
    ),
    (
        "TOPIC_CRIT",
        "TOML/JSON ntfy topic name for handles=[critical]",
    ),
    (
        "CASCADE_ENABLED",
        "TOML [cascade].default_enabled_for_webhook",
    ),
    ("KLAXOND_EMERGENCY_ENABLED", "TOML [emergency].enabled"),
    (
        "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
        "TOML [emergency].allow_insecure_public_url",
    ),
    (
        "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY",
        "TOML [emergency].allow_ntfy_only",
    ),
    (
        "KLAXOND_EMERGENCY_SEVERITIES",
        "TOML [emergency.profiles] fallback severities",
    ),
    (
        "KLAXOND_EMERGENCY_RETRY_SECONDS",
        "TOML [emergency.profiles] fallback retry_seconds",
    ),
    (
        "KLAXOND_EMERGENCY_EXPIRE_SECONDS",
        "TOML [emergency.profiles] fallback expire_seconds",
    ),
    (
        "KLAXOND_EMERGENCY_MAX_ATTEMPTS",
        "TOML [emergency.profiles] fallback max_attempts",
    ),
    (
        "KLAXOND_EMERGENCY_LEASE_SECONDS",
        "TOML [emergency.profiles] fallback lease_seconds",
    ),
    (
        "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
        "TOML [emergency.profiles.telegram] fallback after_attempts",
    ),
    (
        "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
        "TOML [emergency.profiles.smtp] fallback after_attempts",
    ),
    (
        "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
        "TOML [emergency.profiles] fallback notify_on_expiry",
    ),
    (
        "KLAXOND_EMERGENCY_AUTO_RESOLVE",
        "TOML [emergency.profiles] fallback auto_resolve",
    ),
    (
        "KLAXOND_EMERGENCY_EXCLUDE_SOURCES",
        "TOML [emergency].exclude_sources",
    ),
    ("TELEGRAM_BOT_TOKEN", "TOML [telegram].bot_token"),
    ("TELEGRAM_CHAT_ID", "TOML [telegram].chat_id"),
    ("TELEGRAM_API_BASE", "TOML [telegram].api_base"),
    ("SMTP_HOST", "TOML [smtp].host"),
    ("SMTP_PORT", "TOML [smtp].port"),
    ("SMTP_STARTTLS", "TOML [smtp].starttls"),
    ("SMTP_USER", "TOML [smtp].user"),
    ("SMTP_PASSWORD", "TOML [smtp].password"),
    ("SMTP_FROM", "TOML [smtp].from_addr"),
    ("SMTP_TO", "TOML [smtp].to_addr"),
    ("GRAFANA_BASE", "TOML [render].grafana_base"),
    ("GRAFANA_RENDER_BASE", "TOML [render].grafana_render_base"),
    ("GRAFANA_RENDER_TOKEN", "TOML [render].grafana_render_token"),
    ("RENDER_IMAGE_TTL", "TOML [render].render_image_ttl"),
    (
        "KLAXOND_SOURCE_URL_UPTIME_KUMA",
        "TOML [render.source_urls].uptime-kuma",
    ),
    (
        "KLAXOND_SOURCE_URL_HEALTHCHECKS",
        "TOML [render.source_urls].healthchecks",
    ),
    ("KLAXOND_SOURCE_URL_WUD", "TOML [render.source_urls].wud"),
    ("KLAXOND_SOURCE_URL_PVE", "TOML [render.source_urls].pve"),
    (
        "KLAXOND_SOURCE_URL_SHELFMARK",
        "TOML [render.source_urls].shelfmark",
    ),
    (
        "KLAXOND_SOURCE_URL_PROWLARR",
        "TOML [render.source_urls].prowlarr",
    ),
    (
        "KLAXOND_SOURCE_URL_DECYPHARR",
        "TOML [render.source_urls].decypharr",
    ),
    (
        "KLAXOND_SOURCE_URL_REVAULTER",
        "TOML [render.source_urls].revaulter",
    ),
    ("KLAXOND_PUBLIC_URL", "TOML [server].public_url"),
    ("ACK_DEFAULT_TTL_SECONDS", "TOML [acks].default_ttl_seconds"),
    ("AUTH_SESSION_SECRET", "TOML/JSON auth.session_secret"),
    (
        "AUTH_OIDC_CLIENT_SECRET",
        "TOML/JSON auth.oidc.client_secret",
    ),
    (
        "AUTH_BASIC_PASSWORD_HASH",
        "TOML/JSON auth.basic.password_hash",
    ),
    (
        "AUTH_TRUSTED_PROXY_CIDRS",
        "TOML/JSON auth.trusted_proxy.trusted_cidrs",
    ),
    (
        "KLAXOND_CUSTOM_INGEST_SOURCES",
        "TOML [ingest.custom_sources]",
    ),
    ("KLAXOND_CUSTOM_INGEST_SECRETS", "TOML [ingest.secrets]"),
    (
        "KLAXOND_INGEST_SECRET_GRAFANA",
        "TOML [ingest.secrets].grafana",
    ),
    (
        "KLAXOND_INGEST_SECRET_BESZEL",
        "TOML [ingest.secrets].beszel",
    ),
    (
        "KLAXOND_INGEST_SECRET_HEALTHCHECKS",
        "TOML [ingest.secrets].healthchecks",
    ),
    (
        "KLAXOND_INGEST_SECRET_UPTIME_KUMA",
        "TOML [ingest.secrets].uptime-kuma",
    ),
    ("KLAXOND_INGEST_SECRET_WUD", "TOML [ingest.secrets].wud"),
    (
        "KLAXOND_INGEST_SECRET_AUTHENTIK",
        "TOML [ingest.secrets].authentik",
    ),
    (
        "KLAXOND_INGEST_SECRET_SHELFMARK",
        "TOML [ingest.secrets].shelfmark",
    ),
    (
        "KLAXOND_INGEST_SECRET_PROWLARR",
        "TOML [ingest.secrets].prowlarr",
    ),
    (
        "KLAXOND_INGEST_SECRET_DECYPHARR",
        "TOML [ingest.secrets].decypharr",
    ),
    ("KLAXOND_INGEST_SECRET_PVE", "TOML [ingest.secrets].pve"),
    (
        "KLAXOND_INGEST_SECRET_BLACKSTART",
        "TOML [ingest.secrets].blackstart",
    ),
    (
        "KLAXOND_INGEST_SECRET_GITHUB",
        "TOML [ingest.secrets].github",
    ),
    (
        "KLAXOND_INGEST_SECRET_REVAULTER",
        "TOML [ingest.secrets].revaulter",
    ),
    ("PORT", "TOML [server].port"),
    ("RENDER_CONFIG_PATH", "TOML [paths].render_config"),
    ("NTFY_TOPICS_PATH", "TOML [paths].ntfy_topics"),
    ("DEDUP_CONFIG_PATH", "TOML [paths].dedup_config"),
    ("AUTH_CONFIG_PATH", "TOML [paths].auth_config"),
    ("AUTH_SESSION_KEY_PATH", "TOML [paths].auth_session_key"),
    ("KLAXOND_BACKUP_DIR", "TOML [paths].backup_dir"),
    ("DEDUP_PENDING_DIR", "TOML [paths].dedup_pending_dir"),
    ("BESZEL_DB_PATH", "TOML [paths].beszel_db"),
    ("KLAXOND_SQLITE_PATH", "TOML [paths].history_db"),
    ("KLAXOND_HISTORY_BACKEND", "TOML [history].backend"),
    ("KLAXOND_POSTGRES_URL", "TOML [history].postgres_url"),
    ("KLAXOND_HISTORY_RETENTION", "TOML [history].retention"),
    (
        "KLAXOND_HISTORY_DEFAULT_LIMIT",
        "TOML [history].default_limit",
    ),
];

const SPLIT_COMPOSE_ENV_KEYS: &[&str] = &[
    "KLAXOND_BACKEND_IMAGE",
    "KLAXOND_BACKEND_CONTAINER",
    "KLAXOND_BACKEND_BIND",
    "KLAXOND_FRONTEND_IMAGE",
    "KLAXOND_FRONTEND_CONTAINER",
    "KLAXOND_FRONTEND_BIND",
    "KLAXOND_FRONTEND_MAX_BODY_SIZE",
    "KLAXOND_BACKEND_URL",
    "KLAXOND_STATE_IMAGE",
    "KLAXOND_STATE_CONTAINER",
    "KLAXOND_DATA_VOLUME",
    "KLAXOND_POSTGRES_IMAGE",
    "KLAXOND_POSTGRES_CONTAINER",
    "KLAXOND_POSTGRES_BIND",
    "KLAXOND_POSTGRES_DB",
    "KLAXOND_POSTGRES_USER",
    "KLAXOND_POSTGRES_PASSWORD",
    "KLAXOND_POSTGRES_VOLUME",
];

fn compose_env_keys(compose: &str) -> Vec<String> {
    compose
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if !line.starts_with("      ") || trimmed.starts_with('#') {
                return None;
            }
            let (key, _) = trimmed.split_once(':')?;
            if key.starts_with("POSTGRES_") {
                return None;
            }
            if key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                Some(key.to_string())
            } else {
                None
            }
        })
        .collect()
}
#[test]
fn compose_env_vars_have_toml_or_json_equivalent_declared() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let compose = fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let compose_keys = compose_env_keys(&compose);
    let mut missing = Vec::new();
    for key in &compose_keys {
        if BOOTSTRAP_ONLY_COMPOSE_ENV_KEYS.contains(&key.as_str()) {
            continue;
        }
        let equivalent = COMPOSE_FILE_CONFIG_EQUIVALENTS
            .iter()
            .find(|(mapped, _)| *mapped == key.as_str())
            .map(|(_, target)| *target);
        match equivalent {
            Some(target) if target.contains("TOML") || target.contains("JSON") => {}
            _ => missing.push(key.clone()),
        }
    }
    assert!(
        missing.is_empty(),
        "compose env vars without TOML/JSON equivalent: {missing:?}"
    );
}
