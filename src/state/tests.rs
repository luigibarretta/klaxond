use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

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

#[test]
fn auth_session_secret_can_come_from_toml_without_key_file() {
    // SAFETY: this test is single-threaded with respect to its env mutation.
    unsafe { std::env::remove_var("AUTH_SESSION_SECRET") };
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    fs::write(
        &paths.config,
        r#"
[auth]
session_secret = "toml-session-secret"
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(&paths).unwrap();
    let key = load_or_create_session_key(&paths, &cfg).unwrap();

    assert_eq!(key, b"toml-session-secret");
    assert!(!paths.auth_session_key.exists());
}

#[test]
fn delivery_history_survives_state_recreation() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let state = AppState::new(paths.clone()).unwrap();
    state.log_delivery("grafana", "warning", "Persist me", "dry-run", "");
    state.log_delivery("grafana", "warning", "Newest", "dry-run", "");
    drop(state);

    let reloaded = AppState::new(paths).unwrap();
    let deliveries = reloaded.recent_deliveries();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(deliveries[0].title, "Newest");
    assert_eq!(deliveries[0].source, "grafana");
}

#[test]
fn state_initialization_creates_backup_dir_for_setup_readiness() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);

    assert!(!paths.backup_dir.exists());
    let _state = AppState::new(paths.clone()).unwrap();

    assert!(paths.backup_dir.is_dir());
}

#[test]
fn history_store_reopens_when_runtime_config_changes() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let state = AppState::new(paths).unwrap();
    state.log_delivery("grafana", "warning", "Original DB", "dry-run", "");

    let mut cfg = state.cfg();
    cfg.history.sqlite_path = tmp.path().join("next.db");
    state.try_replace_config(cfg).unwrap();
    state.log_delivery("grafana", "warning", "Next DB", "dry-run", "");

    let deliveries = state.recent_deliveries();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].title, "Next DB");
}

#[test]
fn history_store_switch_preserves_runtime_auth_state() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let state = AppState::new(paths).unwrap();
    let now = crate::util::now_epoch_i64();
    let session = crate::history::AuthSessionRecord {
        id_hash: "session-hash".to_string(),
        family_hash: "session-family".to_string(),
        user_json: "{}".to_string(),
        user_sub: "alice".to_string(),
        auth_mode: "oidc".to_string(),
        provider_issuer: Some("https://idp.example.test".to_string()),
        provider_session_id: Some("provider-session".to_string()),
        created_at: now,
        last_seen_at: now,
        last_rotated_at: now,
        expires_at: now + 3600,
        revoked_at: None,
    };
    state
        .history_store()
        .create_auth_session(&session, None, 3, now)
        .unwrap();
    for _ in 0..10 {
        state
            .history_store()
            .record_auth_failure("rate-key-hash", now)
            .unwrap();
    }

    let mut cfg = state.cfg();
    cfg.history.sqlite_path = tmp.path().join("replacement.db");
    state.try_replace_config(cfg).unwrap();

    assert!(
        state
            .history_store()
            .auth_session("session-hash", now, 1800)
            .unwrap()
            .is_some()
    );
    assert!(
        state
            .history_store()
            .auth_rate_limited("rate-key-hash", now)
            .unwrap()
    );
}

#[test]
fn failed_config_commit_keeps_the_active_history_store() {
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let state = AppState::new(paths).unwrap();
    let original_history = state.cfg().history;
    let replacement = tmp.path().join("failed-replacement.db");
    let mut cfg = state.cfg();
    cfg.history.sqlite_path = replacement.clone();
    let rollback_called = std::cell::Cell::new(false);

    let result: Result<(), String> = state.try_replace_config_with_commit(
        cfg,
        || Err("persist failed".to_string()),
        || {
            rollback_called.set(true);
            Ok(())
        },
    );

    assert_eq!(result.unwrap_err(), "persist failed");
    assert!(rollback_called.get());
    assert_eq!(state.cfg().history, original_history);
    assert!(!replacement.exists());
}

#[test]
fn oidc_provider_generation_tracks_only_provider_inputs() {
    let tmp = TempDir::new().unwrap();
    let state = AppState::new(temp_paths(&tmp)).unwrap();
    let initial = state
        .oidc_config_generation
        .load(std::sync::atomic::Ordering::Relaxed);

    let mut unrelated = state.cfg();
    unrelated.port += 1;
    state.try_replace_config(unrelated).unwrap();
    assert_eq!(
        state
            .oidc_config_generation
            .load(std::sync::atomic::Ordering::Relaxed),
        initial
    );

    let mut public_origin = state.cfg();
    public_origin.public_url = "https://klaxond.example.test".to_string();
    state.try_replace_config(public_origin).unwrap();
    assert_eq!(
        state
            .oidc_config_generation
            .load(std::sync::atomic::Ordering::Relaxed),
        initial + 1
    );

    let mut provider = state.cfg();
    provider.auth.oidc.issuer = "https://idp.example.test/application/o/klaxond/".to_string();
    state.try_replace_config(provider).unwrap();
    assert_eq!(
        state
            .oidc_config_generation
            .load(std::sync::atomic::Ordering::Relaxed),
        initial + 2
    );
}
