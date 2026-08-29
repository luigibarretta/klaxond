use super::*;

#[test]
fn emergency_policy_parses_production_bounds() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let value: toml::Value = toml::from_str(
        r#"
[emergency]
enabled = true
allow_insecure_public_url = false
allow_ntfy_only = false
severities = ["critical"]
retry_seconds = 60
expire_seconds = 3600
max_attempts = 50
lease_seconds = 30
telegram_after_attempts = 3
smtp_after_attempts = 5
notify_on_expiry = true
auto_resolve = true
exclude_sources = ["api-test"]
"#,
    )
    .unwrap();

    let cfg = super::super::readers::read_emergency(&value).unwrap();
    assert!(cfg.enabled);
    assert!(!cfg.allow_insecure_public_url);
    assert!(!cfg.allow_ntfy_only);
    assert_eq!(cfg.retry_seconds, 60);
    assert_eq!(cfg.expire_seconds, 3_600);
    assert_eq!(cfg.max_attempts, 50);
    assert_eq!(cfg.exclude_sources, ["api-test"]);
}

#[test]
fn emergency_policy_rejects_overflow_and_zero_escalation() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let overflow: toml::Value = toml::from_str(
        "[emergency]\nmax_attempts=4294967297\ntelegram_after_attempts=3\nsmtp_after_attempts=5",
    )
    .unwrap();
    assert!(super::super::readers::read_emergency(&overflow).is_err());

    let zero: toml::Value = toml::from_str(
        "[emergency]\nmax_attempts=50\ntelegram_after_attempts=0\nsmtp_after_attempts=5",
    )
    .unwrap();
    assert!(super::super::readers::read_emergency(&zero).is_err());
}

#[test]
fn emergency_policy_rejects_malformed_environment_values() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    // SAFETY: this test holds TEST_ENV_LOCK for the full mutation window.
    unsafe {
        std::env::set_var("KLAXOND_EMERGENCY_ENABLED", "treu");
    }
    let error = super::super::readers::read_emergency(&toml::Value::Table(Default::default()))
        .unwrap_err()
        .to_string();
    clear_runtime_env();
    assert!(error.contains("KLAXOND_EMERGENCY_ENABLED must be a boolean"));
}
