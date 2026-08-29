use super::*;

#[test]
fn hashes_new_passwords_with_argon2id_phc() {
    let hash = hash_password("correct horse battery staple").unwrap();

    assert!(hash.starts_with("$argon2id$"));
    assert!(is_argon2_hash(&hash));
    assert!(verify_password("correct horse battery staple", &hash));
    assert!(!verify_password("wrong password", &hash));
}

#[test]
fn rejects_non_argon2id_phc_variants() {
    let hash = hash_password("correct horse battery staple").unwrap();
    let argon2i = hash.replacen("$argon2id$", "$argon2i$", 1);
    let argon2d = hash.replacen("$argon2id$", "$argon2d$", 1);
    let legacy_hash = format!(
        "${}${}",
        "2b", "$12$abcdefghijklmnopqrstuuQH3lTptjPj7P5GupzDVm3Q6xVmH0LqG"
    );

    assert!(!is_argon2_hash(&argon2i));
    assert!(!is_argon2_hash(&argon2d));
    assert!(!is_argon2_hash(&legacy_hash));
    assert!(!verify_password("correct horse battery staple", &argon2i));
    assert!(!verify_password("correct horse battery staple", &argon2d));
    assert!(!verify_password(
        "correct horse battery staple",
        &legacy_hash
    ));
}

#[test]
fn default_policy_enforces_gold_minimum_length() {
    let policy = PasswordPolicy::default();

    assert_eq!(
        policy.validate("short", Some("alice")),
        Err(PolicyError::TooShort { min: 12, actual: 5 })
    );
    assert!(policy.validate("long-enough-pass", Some("alice")).is_ok());
}

#[test]
fn gold_policy_rejects_common_passwords_and_username_substrings() {
    let policy = PasswordPolicy::gold_standard();

    assert_eq!(
        policy.validate("password123", Some("alice")),
        Err(PolicyError::TooShort {
            min: 12,
            actual: 11
        })
    );
    assert_eq!(
        policy.validate("welcome12345", Some("alice")),
        Err(PolicyError::CommonPassword)
    );
    assert_eq!(
        policy.validate("change me 123", Some("alice")),
        Err(PolicyError::CommonPassword)
    );
    assert_eq!(
        policy.validate("Alice-has-a-long-password", Some("alice")),
        Err(PolicyError::ContainsUsername)
    );
    assert!(policy
        .validate("long unique password", Some("alice"))
        .is_ok());
}

#[test]
fn policy_errors_have_stable_codes() {
    let error = validate_gold_standard("short", Some("alice")).unwrap_err();

    assert_eq!(error.code(), "password_too_short");
    assert_eq!(error.message(), "password must be at least 12 characters");
}

#[test]
fn gold_policy_enforces_maximum_length() {
    let policy = PasswordPolicy::gold_standard();
    let password = "x".repeat(GOLD_STANDARD_MAX_PASSWORD_LENGTH + 1);

    assert_eq!(
        policy.validate(&password, None),
        Err(PolicyError::TooLong {
            max: GOLD_STANDARD_MAX_PASSWORD_LENGTH,
            actual: GOLD_STANDARD_MAX_PASSWORD_LENGTH + 1,
        })
    );
}
