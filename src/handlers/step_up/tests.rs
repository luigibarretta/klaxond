use super::*;
use crate::config::Paths;
use auth_modules::totp::{base32_decode, current_step, hotp_code};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn registered_totp_counter_is_consumed_once() {
    let tmp = TempDir::new().expect("tempdir");
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().expect("env lock");
        AppState::new(temp_paths(&tmp)).expect("state")
    };
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let now = now_epoch_i64();
    let counter = u64::try_from(current_step(now)).expect("current counter");
    let code = hotp_code(
        &base32_decode(secret).expect("base32 secret"),
        counter,
        auth_modules::totp::DEFAULT_DIGITS,
    )
    .expect("TOTP code");
    let mut cfg = state.cfg();
    cfg.auth.totp_factors.push(TotpRecord {
        id: "totp-1".to_string(),
        name: "Authenticator".to_string(),
        user_sub: "user-1".to_string(),
        user_name: "User".to_string(),
        user_email: "user@example.test".to_string(),
        secret: secret.to_string(),
        created_at: now,
        last_used_at: None,
        last_used_counter: None,
    });
    state.replace_config(cfg);

    assert!(consume_totp_factor(&state, "user-1", &code).expect("first consume"));
    assert!(!consume_totp_factor(&state, "user-1", &code).expect("replay consume"));
    assert_eq!(
        state.cfg().auth.totp_factors[0].last_used_counter,
        Some(counter)
    );
}

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
