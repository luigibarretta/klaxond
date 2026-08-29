mod crypto;
mod policy;
mod record;

pub use crypto::{generate_token, hash_token};
pub use policy::{
    OneTimeTokenPolicy, OneTimeTokenPurpose, DEFAULT_ONE_TIME_TOKEN_BYTES, EMAIL_VERIFICATION_TTL,
    MAGIC_LINK_TTL, PASSWORD_RESET_TTL,
};
pub use record::{
    verify_and_consume, GeneratedOneTimeToken, OneTimeTokenRecord, OneTimeTokenRejection,
    OneTimeTokenVerification,
};

pub fn issue_token(
    subject: impl Into<String>,
    purpose: OneTimeTokenPurpose,
    policy: OneTimeTokenPolicy,
    now_epoch: i64,
) -> GeneratedOneTimeToken {
    let plaintext = generate_token(policy.token_bytes);
    let token_hash = hash_token(&plaintext);
    let ttl = i64::try_from(policy.ttl.as_secs()).unwrap_or(i64::MAX);

    GeneratedOneTimeToken {
        plaintext,
        record: OneTimeTokenRecord {
            subject: subject.into(),
            purpose: purpose.as_str().to_string(),
            token_hash,
            issued_at_epoch: now_epoch,
            expires_at_epoch: now_epoch.saturating_add(ttl),
            consumed_at_epoch: None,
        },
    }
}

pub fn generic_delivery_acknowledgement() -> &'static str {
    "If the account exists, a sign-in link has been sent."
}

#[cfg(test)]
mod tests;
