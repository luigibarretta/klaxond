use super::*;
use crate::config::auth_sidecar::load_auth;
use std::collections::HashMap;

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
fn selective_noise_rules_load_from_toml() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let config: toml::Value = toml::from_str(
        r#"
[dedup.grafana]
repeat_suppression_enabled = true

[[dedup.grafana.rules]]
name = "Filesystem alerts"
field = "label"
label = "alertname"
operator = "regex"
pattern = "^Filesystem.*"
action = "suppress"
cooldown_s = 14400
include_critical = true
"#,
    )
    .unwrap();
    save_toml(&paths, &config).unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    let rules = &cfg.dedup["grafana"].rules;

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "Filesystem alerts");
    assert_eq!(rules[0].field, NoiseMatchField::Label);
    assert_eq!(rules[0].label, "alertname");
    assert_eq!(rules[0].operator, NoiseMatchOperator::Regex);
    assert_eq!(rules[0].pattern, "^Filesystem.*");
    assert_eq!(rules[0].action, NoiseRuleAction::Suppress);
    assert_eq!(rules[0].cooldown_s, 14_400);
    assert!(rules[0].include_critical);
}

fn save_stale_sidecars(paths: &Paths) {
    save_ntfy_topics(
        paths,
        &[NtfyTopic {
            name: "stale-topic".into(),
            token: "stale-token".into(),
            handles: vec!["critical".into(), "warning".into()],
        }],
    )
    .unwrap();
    save_auth(
        paths,
        &AuthConfig {
            mode: "none".into(),
            ..AuthConfig::default()
        },
    )
    .unwrap();
    save_render_config(
        paths,
        &HashMap::from([("host".into(), ["Stale".to_string(), "/d/stale".to_string()])]),
    )
    .unwrap();
    save_dedup(
        paths,
        &HashMap::from([(
            "wud".into(),
            DedupSetting {
                enabled: true,
                window_s: 999,
                strategy: "key".into(),
                override_critical: false,
                repeat_suppression_enabled: true,
                repeat_window_s: 7_200,
                repeat_override_critical: false,
                rules: Vec::new(),
            },
        )]),
    )
    .unwrap();
}

fn restored_toml() -> toml::Value {
    toml::from_str(
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
    .unwrap()
}

#[test]
fn restore_sidecars_from_toml_replaces_stale_sidecar_values() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    save_stale_sidecars(&paths);
    let restored_toml = restored_toml();
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
    assert!(!cfg.dedup["wud"].repeat_suppression_enabled);
    assert_eq!(cfg.dedup["wud"].repeat_window_s, 7_200);
    assert!(!cfg.dedup["wud"].repeat_override_critical);
}

#[test]
fn repeat_window_is_bounded_for_toml_and_json_sidecars() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();

    for sidecar in [false, true] {
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        if sidecar {
            let mut settings = default_dedup();
            let setting = settings.get_mut("grafana").expect("grafana setting");
            setting.repeat_window_s = 999_999;
            std::fs::write(&paths.dedup_config, serde_json::to_vec(&settings).unwrap()).unwrap();
        } else {
            std::fs::write(&paths.config, "[dedup.grafana]\nrepeat_window_s = 999999\n").unwrap();
        }

        let cfg = load_runtime_config(&paths).unwrap();
        assert_eq!(cfg.dedup["grafana"].repeat_window_s, 604_800);
    }
}

#[test]
fn dedup_sidecar_adds_and_persists_new_supported_sources() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut legacy = default_dedup();
    legacy.remove("uptime-kuma");
    std::fs::write(
        &paths.dedup_config,
        serde_json::to_vec_pretty(&legacy).unwrap(),
    )
    .unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    assert!(cfg.dedup.contains_key("uptime-kuma"));

    let persisted: HashMap<String, DedupSetting> =
        serde_json::from_slice(&std::fs::read(&paths.dedup_config).unwrap()).unwrap();
    assert!(persisted.contains_key("uptime-kuma"));
    assert_eq!(persisted.len(), DEDUP_SOURCES.len());
}
