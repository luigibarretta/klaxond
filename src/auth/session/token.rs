use crate::state::AppState;
use crate::state::keys::SESSION_ROTATION;
use crate::util::token_urlsafe;
use auth_modules::one_time_token::hash_token;

const SESSION_TOKEN_PREFIX: &str = "klx_sess_";

pub(super) fn new_session_token() -> String {
    format!("{SESSION_TOKEN_PREFIX}{}", token_urlsafe(32))
}

fn rotation_input(predecessor_hash: &str) -> String {
    format!("klaxond.session.rotation.v1:{predecessor_hash}")
}

pub(super) fn rotated_session_token(state: &AppState, predecessor_hash: &str) -> String {
    let input = rotation_input(predecessor_hash);
    format!(
        "{SESSION_TOKEN_PREFIX}{}",
        state.keys.sign_hex(SESSION_ROTATION, input.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::temp_paths;
    use crate::util::hmac_hex;
    use tempfile::TempDir;

    #[test]
    fn rotation_successor_is_not_the_raw_secret_token() {
        let tmp = TempDir::new().unwrap();
        let state = AppState::new(temp_paths(&tmp)).unwrap();
        let secret = std::fs::read(&state.paths.auth_session_key).unwrap();
        let input = rotation_input("predecessor");
        let raw = format!(
            "{SESSION_TOKEN_PREFIX}{}",
            hmac_hex(&secret, input.as_bytes())
        );
        let successor = rotated_session_token(&state, "predecessor");
        assert_ne!(successor, raw);
        assert!(persistent_session_hash(&successor).is_some());
    }
}
