use crate::state::AppState;
use crate::util::{hmac_hex, token_urlsafe};
use auth_modules::one_time_token::hash_token;

const SESSION_TOKEN_PREFIX: &str = "klx_sess_";

pub(super) fn new_session_token() -> String {
    format!("{SESSION_TOKEN_PREFIX}{}", token_urlsafe(32))
}

pub(super) fn rotated_session_token(state: &AppState, predecessor_hash: &str) -> String {
    let input = format!("klaxond.session.rotation.v1:{predecessor_hash}");
    format!(
        "{SESSION_TOKEN_PREFIX}{}",
        hmac_hex(state.session_key.as_slice(), input.as_bytes())
    )
}

pub(in crate::auth) fn persistent_session_hash(cookie_value: &str) -> Option<String> {
    let token = cookie_value.strip_prefix(SESSION_TOKEN_PREFIX)?;
    if token.len() < 32
        || token.len() > 128
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some(hash_token(cookie_value))
}
