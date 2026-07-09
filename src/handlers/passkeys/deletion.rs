use super::super::{json_response, text};
use crate::auth::User;
use crate::config::save_auth;
use crate::state::AppState;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use serde_json::json;

pub(in crate::handlers) fn passkey_delete(
    state: &AppState,
    id: &str,
    current_user: Option<&User>,
) -> Response<Body> {
    if id.is_empty() {
        return text(StatusCode::BAD_REQUEST, "passkey id is required");
    }
    state
        .with_config_write_lock(|| {
            let mut cfg = state.cfg();
            let before = cfg.auth.passkeys.len();
            cfg.auth.passkeys.retain(|record| {
                if record.id != id {
                    return true;
                }
                if let Some(user) = current_user
                    && user.mode == "passkey"
                    && user.sub != record.user_sub
                {
                    return true;
                }
                false
            });
            if cfg.auth.passkeys.len() == before {
                return text(StatusCode::NOT_FOUND, "passkey not found");
            }
            if let Err(err) = save_auth(&state.paths, &cfg.auth) {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            state.replace_config(cfg);
            json_response(json!({"ok": true}))
        })
        .unwrap_or_else(|err| text(StatusCode::INTERNAL_SERVER_ERROR, &err))
}
