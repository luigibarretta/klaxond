use super::*;

#[test]
fn base32_round_trips_rfc_secret() {
    let raw = b"12345678901234567890";
    let encoded = base32_encode(raw);

    assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(base32_decode(&encoded).unwrap(), raw);
    assert_eq!(
        base32_decode("gez dgn-bvgy3tqojqgez dgnbvgy3tqojq").unwrap(),
        raw
    );
}

#[test]
fn hotp_matches_rfc_4226_vectors() {
    let secret = b"12345678901234567890";
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    for (counter, code) in expected.into_iter().enumerate() {
        assert_eq!(hotp_code(secret, counter as u64, 6).as_deref(), Some(code));
    }
}

#[test]
fn totp_verification_accepts_current_and_adjacent_steps() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    assert!(verify_code(secret, "755224", 30));
    assert!(verify_code(secret, "287082", 30));
    assert!(verify_code(secret, "359152", 30));
    assert!(!verify_code(secret, "969429", 30));
    assert!(!verify_code(secret, "not-a-code", 30));
    assert_eq!(verify_code_counter(secret, "287082", 30), Some(1));
}

#[test]
fn totp_rejects_weak_secrets_and_pathological_configuration() {
    let weak_secret = base32_encode(b"too-short");
    assert!(!verify_code(&weak_secret, "000000", 30));
    assert!(!verify_code_with_config(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "287082",
        30,
        TotpConfig {
            step_seconds: 0,
            allowed_skew_steps: i64::MIN,
            digits: 1,
        },
    ));
}

#[test]
fn otpauth_uri_uses_shared_shape() {
    let uri = otpauth_uri_with_issuer_prefix("luigi@example.com", "SceneTrove", "SECRET");

    assert_eq!(
        uri,
        "otpauth://totp/SceneTrove%3Aluigi%40example.com?secret=SECRET&issuer=SceneTrove&algorithm=SHA1&digits=6&period=30"
    );
}
