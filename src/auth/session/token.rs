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

/// The successor a rotation performed before 0.23 (raw-secret HMAC) would
/// have produced. A browser that lost that rotation response still presents
/// the predecessor; looking this successor up too keeps it signed in.
pub(super) fn legacy_rotated_session_token(state: &AppState, predecessor_hash: &str) -> String {
    let input = rotation_input(predecessor_hash);
    format!(
        "{SESSION_TOKEN_PREFIX}{}",
        state.keys.legacy_hex(input.as_bytes())
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
    fn legacy_rotation_successor_matches_the_pre_derivation_token() {
        let tmp = TempDir::new().unwrap();
        let state = AppState::new(temp_paths(&tmp)).unwrap();
        let secret = std::fs::read(&state.paths.auth_session_key).unwrap();
        let input = rotation_input("predecessor");
        let legacy = format!(
            "{SESSION_TOKEN_PREFIX}{}",
            hmac_hex(&secret, input.as_bytes())
        );
        assert_eq!(legacy_rotated_session_token(&state, "predecessor"), legacy);
        assert_ne!(rotated_session_token(&state, "predecessor"), legacy);
        assert!(persistent_session_hash(&legacy).is_some());
    }
}
