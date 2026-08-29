use super::*;

#[test]
fn issued_tokens_are_hashed_and_expiring() {
    let generated = issue_token(
        "alice@example.test",
        OneTimeTokenPurpose::MagicLink,
        OneTimeTokenPolicy::magic_link(),
        1_000,
    );

    assert_ne!(generated.plaintext, generated.record.token_hash);
    assert_eq!(generated.record.purpose, "magic_link");
    assert_eq!(generated.record.expires_at_epoch, 1_600);
}

#[test]
fn token_can_be_consumed_once() {
    let generated = issue_token(
        "alice",
        OneTimeTokenPurpose::PasswordReset,
        OneTimeTokenPolicy::password_reset(),
        100,
    );
    let mut record = generated.record;

    assert_eq!(
        verify_and_consume(
            &mut record,
            &generated.plaintext,
            &OneTimeTokenPurpose::PasswordReset,
            120
        ),
        OneTimeTokenVerification::Accepted
    );
    assert_eq!(
        verify_and_consume(
            &mut record,
            &generated.plaintext,
            &OneTimeTokenPurpose::PasswordReset,
            121
        ),
        OneTimeTokenVerification::Rejected(OneTimeTokenRejection::AlreadyConsumed)
    );
}

#[test]
fn wrong_purpose_and_expired_tokens_are_rejected() {
    let generated = issue_token(
        "alice",
        OneTimeTokenPurpose::MagicLink,
        OneTimeTokenPolicy::magic_link(),
        100,
    );
    let mut wrong_purpose = generated.record.clone();
    let mut expired = generated.record;

    assert_eq!(
        verify_and_consume(
            &mut wrong_purpose,
            &generated.plaintext,
            &OneTimeTokenPurpose::EmailVerification,
            120
        ),
        OneTimeTokenVerification::Rejected(OneTimeTokenRejection::WrongPurpose)
    );
    assert_eq!(
        verify_and_consume(
            &mut expired,
            &generated.plaintext,
            &OneTimeTokenPurpose::MagicLink,
            700
        ),
        OneTimeTokenVerification::Rejected(OneTimeTokenRejection::Expired)
    );
}

#[test]
fn generated_token_debug_redacts_plaintext_and_hash() {
    let generated = issue_token(
        "user-1",
        OneTimeTokenPurpose::MagicLink,
        OneTimeTokenPolicy::magic_link(),
        1_000,
    );
    let debug = format!("{generated:?}");

    assert!(debug.contains("user-1"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&generated.plaintext));
    assert!(!debug.contains(&generated.record.token_hash));
}
