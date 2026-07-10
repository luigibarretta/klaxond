use super::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

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

[auth.step_up]
required_after_primary = true
factor = "totp"

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
    assert!(cfg.auth.step_up.required_after_primary);
    assert_eq!(cfg.auth.step_up.factor, "totp");
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
