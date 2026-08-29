use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

mod emergency;
mod env_contract;
mod preflight;
mod runtime_sources;
mod sidecar_restore;

#[test]
fn runtime_version_matches_crate_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn dedup_defaults_cover_every_supported_source() {
    let defaults = default_dedup();

    assert_eq!(defaults.len(), DEDUP_SOURCES.len());
    for source in DEDUP_SOURCES {
        assert!(
            defaults.contains_key(*source),
            "missing dedup defaults for {source}"
        );
    }
}

#[test]
fn ingest_sources_cover_non_deduplicated_routes() {
    assert!(INGEST_SOURCES.contains(&"pve"));
    assert!(INGEST_SOURCES.contains(&"blackstart"));
    assert!(
        DEDUP_SOURCES
            .iter()
            .all(|source| INGEST_SOURCES.contains(source))
    );
}

#[test]
fn resolved_notifications_fall_back_to_info_topic() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = load_runtime_config(&temp_paths(&tmp)).unwrap();
    cfg.ntfy_topics = vec![
        NtfyTopic {
            name: "info-topic".into(),
            token: "info-token".into(),
            handles: vec!["info".into()],
        },
        NtfyTopic {
            name: "critical-topic".into(),
            token: "critical-token".into(),
            handles: vec!["critical".into()],
        },
    ];

    let topics = cfg.topics_for("resolved");
    assert_eq!(topics.len(), 1);
    assert_eq!(topics[0].name, "info-topic");
}

#[test]
fn dedicated_resolved_topic_takes_precedence_over_info_fallback() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = load_runtime_config(&temp_paths(&tmp)).unwrap();
    cfg.ntfy_topics = vec![
        NtfyTopic {
            name: "info-topic".into(),
            token: "info-token".into(),
            handles: vec!["info".into()],
        },
        NtfyTopic {
            name: "resolved-topic".into(),
            token: "resolved-token".into(),
            handles: vec!["resolved".into()],
        },
    ];

    let topics = cfg.topics_for("resolved");
    assert_eq!(topics.len(), 1);
    assert_eq!(topics[0].name, "resolved-topic");
}

#[test]
fn ldap_config_builds_shared_direct_bind_config() {
    let ldap = LdapConfig {
        url: "ldaps://directory.example.com:636".to_string(),
        bind_dn_template: "uid={username},ou=people,dc=example,dc=com".to_string(),
        scope: "one".to_string(),
        timeout_secs: 99,
        ..LdapConfig::default()
    };

    let shared = ldap.to_auth_modules_config().expect("shared config");

    assert_eq!(shared.url, "ldaps://directory.example.com:636");
    assert_eq!(
        shared.bind_dn_template.as_deref(),
        Some("uid={username},ou=people,dc=example,dc=com")
    );
    assert_eq!(auth_modules::ldap::ldap_scope_name(shared.scope), "one");
    assert_eq!(shared.timeout_secs, 60);
}

#[test]
fn ldap_config_requires_bind_strategy() {
    let ldap = LdapConfig {
        url: "ldap://directory.example.com:389".to_string(),
        ..LdapConfig::default()
    };
    assert!(ldap.to_auth_modules_config().is_none());

    let ldap = LdapConfig {
        service_bind_dn: "cn=svc,dc=example,dc=com".to_string(),
        service_bind_password: "secret".to_string(),
        ..ldap
    };
    assert!(ldap.to_auth_modules_config().is_some());
}

const RUNTIME_COMPOSE_ENV_KEYS: &[&str] = &[
    "NTFY_URL",
    "NTFY_TOKEN_INFO",
    "NTFY_TOKEN_WARN",
    "NTFY_TOKEN_CRIT",
    "TOPIC_INFO",
    "TOPIC_WARN",
    "TOPIC_CRIT",
    "CASCADE_ENABLED",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "TELEGRAM_API_BASE",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_STARTTLS",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "SMTP_TO",
    "GRAFANA_BASE",
    "GRAFANA_RENDER_BASE",
    "GRAFANA_RENDER_TOKEN",
    "RENDER_IMAGE_TTL",
    "KLAXOND_SOURCE_URL_UPTIME_KUMA",
    "KLAXOND_SOURCE_URL_HEALTHCHECKS",
    "KLAXOND_SOURCE_URL_WUD",
    "KLAXOND_SOURCE_URL_PVE",
    "KLAXOND_SOURCE_URL_SHELFMARK",
    "KLAXOND_SOURCE_URL_PROWLARR",
    "KLAXOND_SOURCE_URL_DECYPHARR",
    "KLAXOND_PUBLIC_URL",
    "ACK_DEFAULT_TTL_SECONDS",
    "KLAXOND_EMERGENCY_ENABLED",
    "KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL",
    "KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY",
    "KLAXOND_EMERGENCY_SEVERITIES",
    "KLAXOND_EMERGENCY_RETRY_SECONDS",
    "KLAXOND_EMERGENCY_EXPIRE_SECONDS",
    "KLAXOND_EMERGENCY_MAX_ATTEMPTS",
    "KLAXOND_EMERGENCY_LEASE_SECONDS",
    "KLAXOND_EMERGENCY_TELEGRAM_AFTER_ATTEMPTS",
    "KLAXOND_EMERGENCY_SMTP_AFTER_ATTEMPTS",
    "KLAXOND_EMERGENCY_NOTIFY_ON_EXPIRY",
    "KLAXOND_EMERGENCY_AUTO_RESOLVE",
    "KLAXOND_EMERGENCY_EXCLUDE_SOURCES",
    "AUTH_SESSION_SECRET",
    "AUTH_OIDC_CLIENT_SECRET",
    "AUTH_BASIC_PASSWORD_HASH",
    "AUTH_TRUSTED_PROXY_CIDRS",
    "KLAXOND_INGEST_SECRET_GRAFANA",
    "KLAXOND_INGEST_SECRET_BESZEL",
    "KLAXOND_INGEST_SECRET_HEALTHCHECKS",
    "KLAXOND_INGEST_SECRET_UPTIME_KUMA",
    "KLAXOND_INGEST_SECRET_WUD",
    "KLAXOND_INGEST_SECRET_AUTHENTIK",
    "KLAXOND_INGEST_SECRET_SHELFMARK",
    "KLAXOND_INGEST_SECRET_PROWLARR",
    "KLAXOND_INGEST_SECRET_DECYPHARR",
    "KLAXOND_INGEST_SECRET_PVE",
    "KLAXOND_INGEST_SECRET_BLACKSTART",
    "PORT",
    "KLAXOND_CONFIG",
    "RENDER_CONFIG_PATH",
    "NTFY_TOPICS_PATH",
    "DEDUP_CONFIG_PATH",
    "AUTH_CONFIG_PATH",
    "AUTH_SESSION_KEY_PATH",
    "KLAXOND_BACKUP_DIR",
    "DEDUP_PENDING_DIR",
    "BESZEL_DB_PATH",
    "KLAXOND_SQLITE_PATH",
    "KLAXOND_HISTORY_BACKEND",
    "KLAXOND_POSTGRES_URL",
    "KLAXOND_HISTORY_RETENTION",
    "KLAXOND_HISTORY_DEFAULT_LIMIT",
];

const BOOTSTRAP_ONLY_COMPOSE_ENV_KEYS: &[&str] = &["KLAXOND_CONFIG"];

fn temp_paths(tmp: &TempDir) -> Paths {
    let data = tmp.path();
    Paths {
        config: data.join("klaxond.toml"),
        default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
        render_config: data.join("render-config.json"),
        ntfy_topics: data.join("ntfy-topics.json"),
        dedup_config: data.join("dedup-config.json"),
        dedup_pending_dir: data.join("dedup_pending"),
        auth_config: data.join("auth-config.json"),
        auth_session_key: data.join("auth-session.key"),
        backup_dir: data.join("backups"),
        static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
        beszel_db: data.join("missing-beszel.db"),
        history_db: data.join("klaxond.db"),
    }
}

fn clear_runtime_env() {
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        // SAFETY: callers hold TEST_ENV_LOCK while mutating process-wide env state.
        unsafe { std::env::remove_var(key) };
    }
}
