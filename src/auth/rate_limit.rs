use crate::state::AppState;
use auth_modules::audit::AuthAuditKind;
use auth_modules::errors;
use auth_modules::rate_limit::{GOLD_AUTH_ACCOUNT_FAILURE_MAX, GOLD_AUTH_ACCOUNT_FAILURE_WINDOW};
use serde_json::json;

pub(super) fn auth_rate_key(action: &str, subject: &str) -> String {
    let subject = subject.trim().to_ascii_lowercase();
    format!(
        "{action}:{}",
        if subject.is_empty() {
            "unknown"
        } else {
            subject.as_str()
        }
    )
}

pub(super) fn auth_rate_limited(state: &AppState, key: &str) -> bool {
    state
        .auth_failures
        .blocked(key, GOLD_AUTH_ACCOUNT_FAILURE_MAX, auth_failure_window())
}

pub(super) fn record_auth_failure(
    state: &AppState,
    key: &str,
    action: &'static str,
    detail: &'static str,
) {
    state.auth_failures.record(key, auth_failure_window());
    let kind = auth_audit_kind_for_failure(action, detail);
    record_auth_audit_failure(key.to_string(), action, kind, detail);
}

pub(super) fn clear_auth_failures(state: &AppState, key: &str) {
    state.auth_failures.clear(key);
}

fn auth_audit_kind_for_failure(action: &str, detail: &str) -> AuthAuditKind {
    if detail == errors::RATE_LIMITED {
        AuthAuditKind::RateLimitExceeded
    } else if action == "auth.ldap" {
        AuthAuditKind::LdapLoginFailure
    } else if detail.contains("TOTP") {
        AuthAuditKind::TotpVerificationFailure
    } else {
        AuthAuditKind::LoginFailure
    }
}

pub(super) fn record_auth_audit_failure(
    actor: String,
    action: &str,
    kind: AuthAuditKind,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    crate::audit::record(
        actor,
        action,
        "error",
        json!({
            "kind": kind.as_str(),
            "reason": detail,
        })
        .to_string(),
    );
}

fn auth_failure_window() -> std::time::Duration {
    GOLD_AUTH_ACCOUNT_FAILURE_WINDOW
}
