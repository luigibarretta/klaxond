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

#[test]
fn basic_user_step_up_verifies_the_builtin_totp() {
    let tmp = TempDir::new().expect("tempdir");
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().expect("env lock");
        AppState::new(temp_paths(&tmp)).expect("state")
    };
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut cfg = state.cfg();
    cfg.auth.basic.username = "luigi".to_string();
    cfg.auth.basic.totp_enabled = true;
    cfg.auth.basic.totp_secret = secret.to_string();
    state.replace_config(cfg);

    let code = totp_code(secret);
    assert!(consume_totp_factor(&state, "luigi", &code).expect("built-in TOTP"));
    assert!(!consume_totp_factor(&state, "luigi", &code).expect("replay"));
    assert!(!consume_totp_factor(&state, "someone-else", &code).expect("other user"));
}

fn totp_code(secret: &str) -> String {
    let counter = u64::try_from(current_step(now_epoch_i64())).expect("current counter");
    hotp_code(
        &base32_decode(secret).expect("base32 secret"),
        counter,
        auth_modules::totp::DEFAULT_DIGITS,
    )
    .expect("TOTP code")
}

fn totp_factor(user_sub: &str, secret: &str) -> TotpRecord {
    TotpRecord {
        id: format!("totp-{user_sub}"),
        name: "Authenticator".to_string(),
        user_sub: user_sub.to_string(),
        user_name: String::new(),
        user_email: String::new(),
        secret: secret.to_string(),
        created_at: 0,
        last_used_at: None,
        last_used_counter: None,
    }
}

fn pending_totp_step_up(state: &AppState, user_sub: &str) -> String {
    let mut user = crate::handlers::auth_admin::anonymous_user();
    user.sub = user_sub.to_string();
    user.mode = "oidc".to_string();
    let token = random_hex(16);
    lock_mutex(&state.step_up_states, "step-up states").insert(
        token.clone(),
        crate::state::PendingStepUpState {
            created_at: crate::util::now_epoch(),
            return_to: "/status".to_string(),
            user,
            factor: "totp".to_string(),
            reason: "test".to_string(),
        },
    );
    token
}

async fn json_of(resp: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

fn start_body(token: &str) -> Bytes {
    Bytes::from(json!({"step_up": token}).to_string())
}

#[test]
fn totp_setup_start_refuses_user_with_existing_factor() {
    let tmp = TempDir::new().expect("tempdir");
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().expect("env lock");
        AppState::new(temp_paths(&tmp)).expect("state")
    };
    let mut cfg = state.cfg();
    cfg.auth
        .totp_factors
        .push(totp_factor("user-1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    state.replace_config(cfg);
    let token = pending_totp_step_up(&state, "user-1");

    let resp = step_up_totp_setup_start(&state, start_body(&token));

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(lock_mutex(&state.totp_registrations, "totp registrations").is_empty());
    assert_eq!(state.cfg().auth.totp_factors.len(), 1);
}

#[test]
fn totp_setup_start_refuses_basic_user_with_builtin_totp() {
    let tmp = TempDir::new().expect("tempdir");
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().expect("env lock");
        AppState::new(temp_paths(&tmp)).expect("state")
    };
    let mut cfg = state.cfg();
    cfg.auth.basic.username = "luigi".to_string();
    cfg.auth.basic.totp_enabled = true;
    cfg.auth.basic.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
    state.replace_config(cfg);
    let token = pending_totp_step_up(&state, "luigi");

    let resp = step_up_totp_setup_start(&state, start_body(&token));

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(state.cfg().auth.totp_factors.is_empty());
}

#[tokio::test]
async fn totp_setup_confirm_never_replaces_a_registered_factor() {
    let tmp = TempDir::new().expect("tempdir");
    let state = {
        let _env_guard = crate::config::TEST_ENV_LOCK.lock().expect("env lock");
        AppState::new(temp_paths(&tmp)).expect("state")
    };
    let token = pending_totp_step_up(&state, "user-1");
    // First-time enrolment is still allowed to start.
    let started = step_up_totp_setup_start(&state, start_body(&token));
    assert_eq!(started.status(), StatusCode::OK);
    let started = json_of(started).await;
    let request_id = started["request_id"]
        .as_str()
        .expect("request id")
        .to_string();
    let attacker_secret = started["secret"].as_str().expect("secret").to_string();

    // The legitimate owner registers a factor before the pending setup confirms.
    let victim_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut cfg = state.cfg();
    cfg.auth
        .totp_factors
        .push(totp_factor("user-1", victim_secret));
    state.replace_config(cfg);

    let body = json!({"request_id": request_id, "code": totp_code(&attacker_secret)});
    let resp = step_up_totp_setup_confirm(&state, Bytes::from(body.to_string()));

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(resp.headers().get(SET_COOKIE).is_none());
    let factors = state.cfg().auth.totp_factors;
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].secret, victim_secret);
    assert!(lock_mutex(&state.totp_registrations, "totp registrations").is_empty());
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
