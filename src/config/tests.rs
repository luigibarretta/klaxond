use super::auth_sidecar::load_auth;
use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn runtime_version_matches_crate_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
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
    "KLAXOND_PUBLIC_URL",
    "ACK_DEFAULT_TTL_SECONDS",
    "AUTH_SESSION_SECRET",
    "AUTH_OIDC_CLIENT_SECRET",
    "AUTH_BASIC_PASSWORD_HASH",
    "KLAXOND_INGEST_SECRET_GRAFANA",
    "KLAXOND_INGEST_SECRET_BESZEL",
    "KLAXOND_INGEST_SECRET_HEALTHCHECKS",
    "KLAXOND_INGEST_SECRET_WUD",
    "KLAXOND_INGEST_SECRET_AUTHENTIK",
    "KLAXOND_INGEST_SECRET_SHELFMARK",
    "KLAXOND_INGEST_SECRET_PROWLARR",
    "KLAXOND_INGEST_SECRET_DECYPHARR",
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
fn auth_sidecar_migrates_legacy_oidc_redirect_without_trimming_issuer_slash() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    save_auth(
        &paths,
        &AuthConfig {
            oidc: OidcConfig {
                issuer: " https://authentik.example/application/o/klaxond/ ".to_string(),
                redirect_path: "/auth/callback".to_string(),
                ..AuthConfig::default().oidc
            },
            ..AuthConfig::default()
        },
    )
    .unwrap();

    let auth = load_auth(&paths, None).unwrap();
    assert_eq!(
        auth.oidc.issuer,
        "https://authentik.example/application/o/klaxond/"
    );
    assert_eq!(auth.oidc.redirect_path, "/api/auth/callback");

    let persisted: AuthConfig =
        serde_json::from_slice(&std::fs::read(&paths.auth_config).unwrap()).unwrap();
    assert_eq!(persisted.oidc.redirect_path, "/api/auth/callback");
}

#[test]
fn render_sidecar_overrides_toml_seed_after_ui_save() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let toml_seed: toml::Value = toml::from_str(
        r#"
[render.component_dashboards]
host = ["TOML dashboard", "/d/toml"]
"#,
    )
    .unwrap();
    save_toml(&paths, &toml_seed).unwrap();
    save_render_config(
        &paths,
        &HashMap::from([(
            "host".into(),
            ["UI dashboard".to_string(), "/d/ui".to_string()],
        )]),
    )
    .unwrap();

    let cfg = load_runtime_config(&paths).unwrap();

    assert_eq!(
        cfg.component_dashboards.get("host").unwrap(),
        &["UI dashboard".to_string(), "/d/ui".to_string()]
    );
}

#[test]
fn restore_sidecars_from_toml_replaces_stale_sidecar_values() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    save_ntfy_topics(
        &paths,
        &[NtfyTopic {
            name: "stale-topic".into(),
            token: "stale-token".into(),
            handles: vec!["critical".into(), "warning".into()],
        }],
    )
    .unwrap();
    save_auth(
        &paths,
        &AuthConfig {
            mode: "none".into(),
            ..AuthConfig::default()
        },
    )
    .unwrap();
    save_render_config(
        &paths,
        &HashMap::from([("host".into(), ["Stale".to_string(), "/d/stale".to_string()])]),
    )
    .unwrap();
    save_dedup(
        &paths,
        &HashMap::from([(
            "wud".into(),
            DedupSetting {
                enabled: true,
                window_s: 999,
                strategy: "key".into(),
                override_critical: false,
            },
        )]),
    )
    .unwrap();
    let restored_toml: toml::Value = toml::from_str(
        r#"
[render.component_dashboards]
host = ["Restored", "/d/restored"]

[auth]
mode = "basic"
session_timeout_hours = 12

[auth.basic]
username = "restored"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$abcdefghijklmnop$abcdefghijklmnopqrstuvwx"
realm = "klaxond"

[ntfy]
topics = [
  { name = "restored-topic", token = "restored-token", handles = ["critical", "warning"] },
]

[dedup.wud]
enabled = false
window_s = 42
strategy = "time"
override_critical = true
"#,
    )
    .unwrap();
    save_toml(&paths, &restored_toml).unwrap();

    let restored = restore_sidecars_from_toml(&paths, &restored_toml).unwrap();
    let cfg = load_runtime_config(&paths).unwrap();

    assert_eq!(restored, vec!["render", "dedup", "auth", "ntfy_topics"]);
    assert_eq!(
        cfg.component_dashboards.get("host").unwrap(),
        &["Restored".to_string(), "/d/restored".to_string()]
    );
    assert_eq!(cfg.auth.mode, "basic");
    assert_eq!(cfg.auth.basic.username, "restored");
    assert_eq!(cfg.topics_for("critical")[0].name, "restored-topic");
    assert_eq!(cfg.topics_for("critical")[0].token, "restored-token");
    assert!(!cfg.dedup["wud"].enabled);
    assert_eq!(cfg.dedup["wud"].window_s, 42);
    assert_eq!(cfg.dedup["wud"].strategy, "time");
    assert!(cfg.dedup["wud"].override_critical);
}

#[test]
fn toml_can_drive_runtime_settings_that_ui_can_edit() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[ntfy]
url = "https://push.example.test"

[ntfy.topics]
info = "info-topic"
warning = "warn-topic"
critical = "crit-topic"

[telegram]
api_base = "https://telegram.example.test/"
bot_token = "toml-telegram-token"
chat_id = "12345"

[smtp]
host = "smtp.example.test"
port = 2525
starttls = false
user = "smtp-user"
password = "smtp-pass"
from_addr = "from@example.test"
to_addr = "to@example.test"

[render]
grafana_base = "https://grafana.example.test/"
grafana_render_base = "https://render.example.test/"
grafana_render_token = "render-token"
render_image_ttl = 42

[server]
port = 19090
public_url = "https://klaxond.example.test/"

[acks]
default_ttl_seconds = 1234

[history]
backend = "sqlite"
retention = 123
default_limit = 45

[auth]
session_secret = "toml-session-secret"

[ingest.secrets]
grafana = "toml-grafana-secret"
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(&paths).unwrap();

    assert_eq!(cfg.ntfy_url, "https://push.example.test");
    assert_eq!(cfg.telegram_api_base, "https://telegram.example.test");
    assert_eq!(cfg.tg_token, "toml-telegram-token");
    assert_eq!(cfg.tg_chat, "12345");
    assert_eq!(cfg.smtp_host, "smtp.example.test");
    assert_eq!(cfg.smtp_port, 2525);
    assert!(!cfg.smtp_starttls);
    assert_eq!(cfg.smtp_user, "smtp-user");
    assert_eq!(cfg.smtp_pass, "smtp-pass");
    assert_eq!(cfg.smtp_from, "from@example.test");
    assert_eq!(cfg.smtp_to, "to@example.test");
    assert_eq!(cfg.grafana_base, "https://grafana.example.test");
    assert_eq!(cfg.grafana_render_base, "https://render.example.test");
    assert_eq!(cfg.grafana_render_token, "render-token");
    assert_eq!(cfg.render_image_ttl, 42);
    assert_eq!(cfg.port, 19090);
    assert_eq!(cfg.public_url, "https://klaxond.example.test");
    assert_eq!(cfg.ack_default_ttl, 1234);
    assert_eq!(cfg.history.backend, "sqlite");
    assert_eq!(cfg.history.retention, 123);
    assert_eq!(cfg.history.default_limit, 45);
    assert_eq!(cfg.auth.session_secret, "toml-session-secret");
    assert_eq!(
        toml_get(&cfg.toml, &["ingest", "secrets", "grafana"]).and_then(|v| v.as_str()),
        Some("toml-grafana-secret")
    );
}

#[test]
fn toml_paths_cover_compose_path_overrides() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[paths]
render_config = "sidecars/render.json"
ntfy_topics = "sidecars/ntfy.json"
dedup_config = "sidecars/dedup.json"
auth_config = "sidecars/auth.json"
auth_session_key = "secrets/session.key"
backup_dir = "backup"
dedup_pending_dir = "pending"
beszel_db = "/external/beszel.db"
history_db = "history/klaxond.db"
"#,
    )
    .unwrap();

    let resolved = paths.resolve_from_config().unwrap();
    let root = tmp.path();

    assert_eq!(resolved.render_config, root.join("sidecars/render.json"));
    assert_eq!(resolved.ntfy_topics, root.join("sidecars/ntfy.json"));
    assert_eq!(resolved.dedup_config, root.join("sidecars/dedup.json"));
    assert_eq!(resolved.auth_config, root.join("sidecars/auth.json"));
    assert_eq!(resolved.auth_session_key, root.join("secrets/session.key"));
    assert_eq!(resolved.backup_dir, root.join("backup"));
    assert_eq!(resolved.dedup_pending_dir, root.join("pending"));
    assert_eq!(resolved.beszel_db, PathBuf::from("/external/beszel.db"));
    assert_eq!(resolved.history_db, root.join("history/klaxond.db"));
}

#[test]
fn env_overrides_toml_for_compose_runtime_settings() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    // SAFETY: this test holds TEST_ENV_LOCK for the full mutation window.
    unsafe {
        std::env::set_var("TELEGRAM_BOT_TOKEN", "env-telegram-token");
        std::env::set_var("TELEGRAM_API_BASE", "https://telegram-env.example.test/");
        std::env::set_var("SMTP_USER", "env-smtp-user");
        std::env::set_var("SMTP_PASSWORD", "env-smtp-pass");
        std::env::set_var("SMTP_STARTTLS", "true");
        std::env::set_var("GRAFANA_RENDER_BASE", "https://render-env.example.test/");
        std::env::set_var("GRAFANA_RENDER_TOKEN", "env-render-token");
        std::env::set_var("RENDER_IMAGE_TTL", "77");
        std::env::set_var("KLAXOND_PUBLIC_URL", "https://klaxond-env.example.test");
        std::env::set_var("ACK_DEFAULT_TTL_SECONDS", "2345");
        std::env::set_var("KLAXOND_HISTORY_BACKEND", "postgres");
        std::env::set_var("KLAXOND_POSTGRES_URL", "postgres://env.example/klaxond");
        std::env::set_var("KLAXOND_HISTORY_RETENTION", "777");
        std::env::set_var("KLAXOND_HISTORY_DEFAULT_LIMIT", "88");
    }

    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[render]
grafana_render_base = "https://render-toml.example.test"
grafana_render_token = "toml-render-token"
render_image_ttl = 42

[telegram]
api_base = "https://telegram-toml.example.test"
bot_token = "toml-telegram-token"

[smtp]
starttls = false
user = "toml-smtp-user"
password = "toml-smtp-pass"

[server]
public_url = "https://klaxond-toml.example.test"

[acks]
default_ttl_seconds = 1234

[history]
backend = "sqlite"
postgres_url = "postgres://toml.example/klaxond"
retention = 123
default_limit = 45
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    assert_eq!(cfg.tg_token, "env-telegram-token");
    assert_eq!(cfg.telegram_api_base, "https://telegram-env.example.test");
    assert_eq!(cfg.smtp_user, "env-smtp-user");
    assert_eq!(cfg.smtp_pass, "env-smtp-pass");
    assert!(cfg.smtp_starttls);
    assert_eq!(cfg.grafana_render_base, "https://render-env.example.test");
    assert_eq!(cfg.grafana_render_token, "env-render-token");
    assert_eq!(cfg.render_image_ttl, 77);
    assert_eq!(cfg.public_url, "https://klaxond-env.example.test");
    assert_eq!(cfg.ack_default_ttl, 2345);
    assert_eq!(cfg.history.backend, "postgres");
    assert_eq!(cfg.history.postgres_url, "postgres://env.example/klaxond");
    assert_eq!(cfg.history.retention, 777);
    assert_eq!(cfg.history.default_limit, 88);

    clear_runtime_env();
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

#[test]
fn reference_compose_and_env_example_cover_runtime_env_vars() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let compose = fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let split_compose = fs::read_to_string(root.join("docker-compose.split.yml")).unwrap();
    let env_example = fs::read_to_string(root.join(".env.example")).unwrap();
    let compose_keys = compose_env_keys(&compose);
    let split_compose_keys = compose_env_keys(&split_compose);
    assert!(
        !compose_keys.is_empty(),
        "docker-compose.yml has no env keys"
    );
    assert!(
        !split_compose_keys.is_empty(),
        "docker-compose.split.yml has no env keys"
    );
    for key in &compose_keys {
        assert!(
            RUNTIME_COMPOSE_ENV_KEYS.contains(&key.as_str()),
            "RUNTIME_COMPOSE_ENV_KEYS missing compose env {key}"
        );
    }
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.yml missing {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing {key}"
        );
    }
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.split.yml missing backend runtime env {key}"
        );
    }
    for key in SPLIT_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("${{{key}")),
            "docker-compose.split.yml missing split env {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing split env {key}"
        );
    }
    assert!(
        split_compose.contains(r#"profiles: ["backend", "all"]"#),
        "split compose must allow backend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["frontend", "all"]"#),
        "split compose must allow frontend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["db", "state", "all"]"#),
        "split compose must allow db/state-only startup"
    );
}

#[test]
fn split_frontend_proxy_template_covers_backend_routes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nginx = fs::read_to_string(root.join("deploy/frontend/nginx.conf.template")).unwrap();

    for expected in [
        "KLAXOND_BACKEND_URL",
        "map $http_x_forwarded_proto $klaxond_forwarded_proto",
        "map $http_host $klaxond_forwarded_host",
        "proxy_set_header Host $klaxond_forwarded_host",
        "proxy_set_header X-Forwarded-Proto $klaxond_forwarded_proto",
        "proxy_set_header X-Forwarded-Host $klaxond_forwarded_host",
        "absolute_redirect off",
        "location ~ ^/api/",
        "location ~ ^/(webhook|beszel|healthchecks|wud|authentik|shelfmark|prowlarr|decypharr|pve)(/|$)",
        "location ~ ^/img/",
        "location ~ ^/(swagger|api/docs|api/swagger|api/swagger-ui)(/|$)",
        "location = /ui/meta.js",
        "location = /ui/auth",
        "return 302 /authentication",
        "try_files $uri /index.html",
    ] {
        assert!(
            nginx.contains(expected),
            "frontend nginx template missing {expected}"
        );
    }
}
