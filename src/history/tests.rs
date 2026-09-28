use super::*;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

mod delivery;
mod emergency;
mod migration;
mod postgres_delivery;
mod postgres_rate_limit;
mod postgres_repeat;
mod postgres_session;
mod rate_limit;
mod repeat;
mod sqlite_session;

fn postgres_test_guard() -> MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn sqlite_cfg(path: PathBuf, retention: usize) -> HistoryConfig {
    HistoryConfig {
        backend: "sqlite".to_string(),
        sqlite_path: path,
        postgres_url: String::new(),
        retention,
        default_limit: 500,
    }
}

fn entry(i: usize) -> DeliveryEntry {
    DeliveryEntry {
        ts: 1000.0 + i as f64,
        source: "grafana".to_string(),
        severity: "warning".to_string(),
        title: format!("Alert {i}"),
        channel: "ntfy".to_string(),
        suppressed_by: String::new(),
        emergency_receipt_id: None,
    }
}

fn repeat_candidate(now: f64, token: &str) -> RepeatCandidate {
    RepeatCandidate {
        fingerprint: "same-rendered-notification".to_string(),
        source: "grafana".to_string(),
        severity: "warning".to_string(),
        title: "Host down".to_string(),
        now,
        window_s: 7_200,
        reservation_token: token.to_string(),
        reservation_ttl_s: 120.0,
        matched_rule: Some("test rule".into()),
    }
}

fn auth_session(id: &str, mode: &str, now: i64) -> AuthSessionRecord {
    AuthSessionRecord {
        id_hash: id.to_string(),
        family_hash: format!("family-{id}"),
        user_json: r#"{"sub":"same-user"}"#.to_string(),
        user_sub: "same-user".to_string(),
        auth_mode: mode.to_string(),
        provider_issuer: (mode == "oidc").then(|| "https://idp.example/".to_string()),
        provider_session_id: (mode == "oidc").then(|| "provider-session".to_string()),
        created_at: now,
        last_seen_at: now,
        last_rotated_at: now,
        expires_at: now + 10_000,
        revoked_at: None,
    }
}

fn logout_token(id: &str, now: i64) -> OidcLogoutTokenRecord {
    OidcLogoutTokenRecord {
        issuer: "https://idp.example/".to_string(),
        token_id_hash: id.to_string(),
        consumed_at: now,
        expires_at: now + 600,
    }
}

fn import_auth_session(store: &HistoryStore, record: AuthSessionRecord) {
    import_auth_state(store, vec![record], Vec::new(), Vec::new());
}

fn import_logout_token(store: &HistoryStore, token: OidcLogoutTokenRecord) {
    import_auth_state(store, Vec::new(), vec![token], Vec::new());
}

fn import_rate_limit(store: &HistoryStore, record: AuthRateLimitRecord) {
    import_auth_state(store, Vec::new(), Vec::new(), vec![record]);
}

fn import_auth_state(
    store: &HistoryStore,
    sessions: Vec<AuthSessionRecord>,
    logout_tokens: Vec<OidcLogoutTokenRecord>,
    rate_limits: Vec<AuthRateLimitRecord>,
) {
    store
        .import_runtime_auth_state(&RuntimeAuthState {
            sessions,
            logout_tokens,
            rate_limits,
        })
        .unwrap();
}
