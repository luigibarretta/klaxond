use crate::audit;
use crate::auth::User;
use crate::endpoints;
use axum::http::StatusCode;

pub(super) fn record_admin_mutation_audit(
    path: &str,
    status: StatusCode,
    authed_user: Option<&User>,
    body_len: usize,
) {
    let Some(action) = endpoints::audit_action_for_post(path) else {
        return;
    };
    audit::record(
        audit_actor(authed_user),
        action,
        if status.is_success() { "ok" } else { "error" },
        format!("{} status={} bytes={}", path, status.as_u16(), body_len),
    );
}

fn audit_actor(user: Option<&User>) -> String {
    user.map(|u| {
        let sub = if u.sub.trim().is_empty() {
            "anonymous"
        } else {
            u.sub.as_str()
        };
        format!("{}:{sub}", u.mode)
    })
    .unwrap_or_else(|| "anonymous".into())
}
