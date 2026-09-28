use super::*;
use crate::util::toml_get;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

mod env;
mod toml;

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
fn auth_env_overrides_preserve_toml_seed_during_sidecar_bootstrap() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[auth.oidc]
client_secret = "toml-oidc-secret"

[auth.basic]
password_hash = "toml-password-hash"

[auth.trusted_proxy]
trusted_cidrs = ["10.0.0.0/8"]
"#,
    )
    .unwrap();
    // SAFETY: this test holds TEST_ENV_LOCK for the full mutation window.
    unsafe {
        std::env::set_var("AUTH_OIDC_CLIENT_SECRET", "env-oidc-secret");
        std::env::set_var("AUTH_BASIC_PASSWORD_HASH", "env-password-hash");
        std::env::set_var("AUTH_TRUSTED_PROXY_CIDRS", "192.0.2.10/32");
    }

    let cfg = load_runtime_config(&paths).unwrap();
    assert_eq!(cfg.auth.oidc.client_secret, "env-oidc-secret");
    assert_eq!(cfg.auth.basic.password_hash, "env-password-hash");
    assert_eq!(cfg.auth.trusted_proxy.trusted_cidrs, vec!["192.0.2.10/32"]);
    let persisted: AuthConfig =
        serde_json::from_slice(&fs::read(&paths.auth_config).unwrap()).unwrap();
    assert_eq!(persisted.oidc.client_secret, "toml-oidc-secret");
    assert_eq!(persisted.basic.password_hash, "toml-password-hash");
    assert_eq!(persisted.trusted_proxy.trusted_cidrs, vec!["10.0.0.0/8"]);

    clear_runtime_env();
}

#[test]
fn whitespace_auth_env_values_do_not_override_or_replace_sidecar_values() {
    let _guard = TEST_ENV_LOCK.lock().unwrap();
    clear_runtime_env();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut sidecar_auth = AuthConfig::default();
    sidecar_auth.oidc.client_secret = "sidecar-oidc-secret".to_string();
    sidecar_auth.basic.password_hash = "sidecar-password-hash".to_string();
    save_auth(&paths, &sidecar_auth).unwrap();
    // SAFETY: this test holds TEST_ENV_LOCK for the full mutation window.
    unsafe {
        std::env::set_var("AUTH_OIDC_CLIENT_SECRET", "   ");
        std::env::set_var("AUTH_BASIC_PASSWORD_HASH", "\t");
    }

    let cfg = load_runtime_config(&paths).unwrap();
    assert_eq!(cfg.auth.oidc.client_secret, "sidecar-oidc-secret");
    assert_eq!(cfg.auth.basic.password_hash, "sidecar-password-hash");
    save_auth(&paths, &cfg.auth).unwrap();
    let persisted: AuthConfig =
        serde_json::from_slice(&fs::read(&paths.auth_config).unwrap()).unwrap();
    assert_eq!(persisted.oidc.client_secret, "sidecar-oidc-secret");
    assert_eq!(persisted.basic.password_hash, "sidecar-password-hash");

    clear_runtime_env();
}
