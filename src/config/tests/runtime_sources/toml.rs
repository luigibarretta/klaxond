use super::*;

const TOML_RUNTIME_CONFIG: &str = r#"
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

[render.source_urls]
pve = "https://proxmox.example.test"

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

[ingest.custom_sources]
"home-assistant" = "Home Assistant"

[ingest.secrets]
grafana = "toml-grafana-secret"
"home-assistant" = "toml-home-assistant-secret"
"#;

#[test]
fn toml_can_drive_runtime_settings_that_ui_can_edit() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(&paths.config, TOML_RUNTIME_CONFIG).unwrap();
    let cfg = load_runtime_config(&paths).unwrap();
    assert_toml_runtime_config(&cfg);
}

fn assert_toml_runtime_config(cfg: &RuntimeConfig) {
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
    assert_eq!(cfg.source_url("pve"), Some("https://proxmox.example.test"));
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
        cfg.custom_ingest_source("home-assistant"),
        Some("Home Assistant")
    );
    assert!(cfg.dedup.contains_key("home-assistant"));
    assert_eq!(
        cfg.ingest_sources().first().map(String::as_str),
        Some("grafana")
    );
    assert_eq!(
        cfg.dedup_sources().first().map(String::as_str),
        Some("grafana")
    );
    assert_eq!(
        toml_get(&cfg.toml, &["ingest", "secrets", "grafana"]).and_then(|v| v.as_str()),
        Some("toml-grafana-secret")
    );
}
