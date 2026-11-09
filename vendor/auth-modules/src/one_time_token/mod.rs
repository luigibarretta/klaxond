mod crypto;
mod delivery;
mod policy;
mod record;

pub use crypto::{generate_token, hash_token};
pub use delivery::{issue_for_delivery, DeliverableToken, StoredTokenHash, TokenDelivery};
pub use policy::{
    OneTimeTokenPolicy, OneTimeTokenPurpose, DEFAULT_ONE_TIME_TOKEN_BYTES, EMAIL_VERIFICATION_TTL,
    MAGIC_LINK_TTL, PASSWORD_RESET_TTL,
};
pub use record::{
    verify_and_consume, GeneratedOneTimeToken, OneTimeTokenRecord, OneTimeTokenRejection,
    OneTimeTokenVerification,
};

/// Issues a token and returns the plaintext as a public field.
///
/// Deprecated because the plaintext can be serialized or returned in an
/// HTTP response by mistake. Use [`issue_for_delivery`] for magic links,
/// password resets, email verification and invites. Tokens that are meant to
/// be shown to the user once (API tokens) can keep using [`generate_token`]
/// and [`hash_token`] directly.
#[deprecated(
    since = "0.2.0",
    note = "use issue_for_delivery: the plaintext then leaves only through a TokenDelivery"
)]
pub fn issue_token(
    subject: impl Into<String>,
    purpose: OneTimeTokenPurpose,
    policy: OneTimeTokenPolicy,
    now_epoch: i64,
) -> GeneratedOneTimeToken {
    let (plaintext, record) = issue_parts(subject.into(), purpose, policy, now_epoch);
    GeneratedOneTimeToken { plaintext, record }
}

fn issue_parts(
    subject: String,
    purpose: OneTimeTokenPurpose,
    policy: OneTimeTokenPolicy,
    now_epoch: i64,
) -> (String, OneTimeTokenRecord) {
    let plaintext = generate_token(policy.token_bytes);
    let token_hash = hash_token(&plaintext);
    let ttl = i64::try_from(policy.ttl.as_secs()).unwrap_or(i64::MAX);

    let record = OneTimeTokenRecord {
        subject,
        purpose: purpose.as_str().to_string(),
        token_hash,
        issued_at_epoch: now_epoch,
        expires_at_epoch: now_epoch.saturating_add(ttl),
        consumed_at_epoch: None,
    };
    (plaintext, record)
}

pub fn generic_delivery_acknowledgement() -> &'static str {
    "If the account exists, a sign-in link has been sent."
}

#[cfg(test)]
#[allow(deprecated)]
mod tests;

#[cfg(test)]
mod delivery_tests;
