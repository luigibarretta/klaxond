use super::*;
use std::fs;
use tempfile::TempDir;

fn emergency_config(extra: &str) -> String {
    format!(
        r#"
[server]
public_url = "https://klaxond.example.test"

[ntfy]
url = "https://push.example.test"

[[ntfy.topics]]
name = "critical-topic"
token = "publish-token-placeholder"
handles = ["critical"]

[telegram]
bot_token = "telegram-token-placeholder"
chat_id = "12345"

[emergency]
enabled = true
severities = ["critical"]
retry_seconds = 60
expire_seconds = 3600
max_attempts = 50
lease_seconds = 60
telegram_after_attempts = 3
smtp_after_attempts = 5
notify_on_expiry = true
auto_resolve = true
exclude_sources = ["api-test"]
{extra}
"#
    )
}

#[test]
fn emergency_preflight_accepts_https_with_ntfy_and_fallback() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(&paths.config, emergency_config("")).unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    assert!(cfg.emergency.enabled);
}

#[test]
fn emergency_preflight_rejects_http_public_callback() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config = emergency_config("").replace(
        "https://klaxond.example.test",
        "http://klaxond.example.test",
    );
    fs::write(&paths.config, config).unwrap();

    let error = load_runtime_config(&paths).unwrap_err().to_string();
    assert!(error.contains("server.public_url must use HTTPS"));
}

#[test]
fn emergency_preflight_rejects_missing_ntfy_publish_token() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config =
        emergency_config("").replace("token = \"publish-token-placeholder\"", "token = \"\"");
    fs::write(&paths.config, config).unwrap();

    let error = load_runtime_config(&paths).unwrap_err().to_string();
    assert!(error.contains("requires an ntfy topic with a publish token"));
}

#[test]
fn emergency_preflight_requires_independent_fallback_by_default() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config = emergency_config("")
        .replace(
            "bot_token = \"telegram-token-placeholder\"",
            "bot_token = \"\"",
        )
        .replace("chat_id = \"12345\"", "chat_id = \"\"");
    fs::write(&paths.config, config).unwrap();

    let error = load_runtime_config(&paths).unwrap_err().to_string();
    assert!(error.contains("requires a complete Telegram or SMTP fallback"));
}

#[test]
fn emergency_preflight_allows_explicit_local_ntfy_only_mode() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config = emergency_config("allow_insecure_public_url = true\nallow_ntfy_only = true")
        .replace(
            "https://klaxond.example.test",
            "http://klaxond.example.test",
        )
        .replace("https://push.example.test", "http://push.example.test")
        .replace(
            "bot_token = \"telegram-token-placeholder\"",
            "bot_token = \"\"",
        )
        .replace("chat_id = \"12345\"", "chat_id = \"\"");
    fs::write(&paths.config, config).unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    assert!(cfg.emergency.allow_insecure_public_url);
    assert!(cfg.emergency.allow_ntfy_only);
}

#[test]
fn emergency_preflight_rejects_lease_shorter_than_channel_budget() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config = emergency_config("").replace("lease_seconds = 60", "lease_seconds = 20");
    fs::write(&paths.config, config).unwrap();

    let error = load_runtime_config(&paths).unwrap_err().to_string();
    assert!(error.contains("emergency.lease_seconds must be at least"));
}

#[test]
fn portable_preflight_rejects_credential_bearing_source_url() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[render]
grafana_base = "https://grafana.example.test"

[render.source_urls]
pve = "https://admin:secret@proxmox.example.test/"
"#,
    )
    .unwrap();

    let error = load_runtime_config(&paths).unwrap_err().to_string();
    assert!(error.contains("render.source_urls.pve must not contain credentials"));
}
