use super::auth_sidecar::load_auth;
use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

mod env_contract;
mod runtime_sources;

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
fn auth_sidecar_migrates_legacy_oidc_passkey_step_up_flag() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut auth = AuthConfig::default();
    auth.step_up.oidc_requires_passkey = true;
    save_auth(&paths, &auth).unwrap();

    let auth = load_auth(&paths, None).unwrap();

    assert!(auth.step_up.required_after_primary);
    assert_eq!(auth.step_up.factor, "passkey");
    assert!(!auth.step_up.oidc_requires_passkey);
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
