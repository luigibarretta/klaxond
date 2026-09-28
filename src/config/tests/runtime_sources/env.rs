use super::*;

const ENV_RUNTIME_CONFIG: &str = r#"
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
"#;

#[test]
fn env_overrides_toml_for_compose_runtime_settings() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut sidecar_auth = AuthConfig::default();
    sidecar_auth.oidc.client_secret = "sidecar-oidc-secret".to_string();
    sidecar_auth.basic.password_hash = "sidecar-password-hash".to_string();
    sidecar_auth.trusted_proxy.trusted_cidrs = vec!["10.0.0.0/8".to_string()];
    save_auth(&paths, &sidecar_auth).unwrap();
    set_runtime_override_env();
    fs::write(&paths.config, ENV_RUNTIME_CONFIG).unwrap();
    let cfg = load_runtime_config(&paths).unwrap();
    assert_env_runtime_config(&cfg, &paths);
    clear_runtime_env();
}

fn set_runtime_override_env() {
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
        std::env::set_var("AUTH_OIDC_CLIENT_SECRET", "env-oidc-secret");
        std::env::set_var("AUTH_BASIC_PASSWORD_HASH", "env-password-hash");
        std::env::set_var(
            "AUTH_TRUSTED_PROXY_CIDRS",
            "192.0.2.10/32, 2001:db8::10/128",
        );
    }
}

fn assert_env_runtime_config(cfg: &RuntimeConfig, paths: &Paths) {
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
    assert_eq!(cfg.auth.oidc.client_secret, "env-oidc-secret");
    assert_eq!(cfg.auth.basic.password_hash, "env-password-hash");
    assert_eq!(
        cfg.auth.trusted_proxy.trusted_cidrs,
        vec!["192.0.2.10/32", "2001:db8::10/128"]
    );
    save_auth(paths, &cfg.auth).unwrap();
    let persisted: AuthConfig =
        serde_json::from_slice(&fs::read(&paths.auth_config).unwrap()).unwrap();
    assert_eq!(persisted.oidc.client_secret, "sidecar-oidc-secret");
    assert_eq!(persisted.basic.password_hash, "sidecar-password-hash");
    assert_eq!(persisted.trusted_proxy.trusted_cidrs, vec!["10.0.0.0/8"]);
}
