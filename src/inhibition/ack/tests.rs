use super::*;
use crate::auth::test_support::temp_paths;
use crate::state::keys::EMERGENCY_ACK;
use crate::util::hmac_hex;
use tempfile::TempDir;

fn state(tmp: &TempDir) -> AppState {
    AppState::new(temp_paths(tmp)).unwrap()
}

/// A token exactly as releases before 0.23 minted it: the raw session
/// secret as the HMAC key.
fn legacy_token(state: &AppState, payload: serde_json::Value) -> String {
    let secret = std::fs::read(&state.paths.auth_session_key).unwrap();
    let body = b64url_no_pad(payload.to_string().as_bytes());
    format!("{body}.{}", hmac_hex(&secret, body.as_bytes()))
}

fn future() -> i64 {
    now_epoch() as i64 + 600
}

#[test]
fn signed_ack_round_trips() {
    let tmp = TempDir::new().unwrap();
    let state = state(&tmp);
    let token = ack_sign(&state, "DiskFull", 600);
    assert_eq!(
        ack_verify(&state, &token),
        (Some("DiskFull".into()), "ok".into())
    );
}

#[test]
fn legacy_inhibition_ack_links_stay_valid_until_expiry() {
    let tmp = TempDir::new().unwrap();
    let state = state(&tmp);
    let live = legacy_token(&state, json!({"a": "DiskFull", "t": 600, "e": future()}));
    assert_eq!(ack_verify(&state, &live).0.as_deref(), Some("DiskFull"));
    let expired = legacy_token(&state, json!({"a": "DiskFull", "t": 600, "e": 1}));
    assert_eq!(ack_verify(&state, &expired), (None, "expired".into()));
}

#[test]
fn emergency_ack_tokens_never_verify_as_inhibition_acks() {
    let tmp = TempDir::new().unwrap();
    let state = state(&tmp);
    let emergency = json!({"r": "receipt-1", "e": future(), "a": "ack"});

    // Legacy: same raw key, so only the payload shape separates them.
    let legacy = legacy_token(&state, emergency.clone());
    assert_eq!(ack_verify(&state, &legacy), (None, "bad-payload".into()));

    // Current: a different derived key per purpose.
    let body = b64url_no_pad(emergency.to_string().as_bytes());
    let current = format!(
        "{body}.{}",
        state.keys.sign_hex(EMERGENCY_ACK, body.as_bytes())
    );
    assert_eq!(ack_verify(&state, &current), (None, "bad-signature".into()));
}

#[test]
fn raw_secret_tags_over_new_payloads_need_the_inhibition_shape() {
    let tmp = TempDir::new().unwrap();
    let state = state(&tmp);
    let no_ttl = legacy_token(&state, json!({"a": "DiskFull", "e": future()}));
    assert_eq!(ack_verify(&state, &no_ttl), (None, "bad-payload".into()));
}
