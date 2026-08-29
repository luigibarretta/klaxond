use std::fmt;

use super::crypto::{constant_time_eq, hash_token};
use super::policy::OneTimeTokenPurpose;

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedOneTimeToken {
    pub plaintext: String,
    pub record: OneTimeTokenRecord,
}

impl fmt::Debug for GeneratedOneTimeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedOneTimeToken")
            .field("plaintext", &"[REDACTED]")
            .field("record", &self.record)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OneTimeTokenRecord {
    pub subject: String,
    pub purpose: String,
    pub token_hash: String,
    pub issued_at_epoch: i64,
    pub expires_at_epoch: i64,
    pub consumed_at_epoch: Option<i64>,
}

impl fmt::Debug for OneTimeTokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTimeTokenRecord")
            .field("subject", &self.subject)
            .field("purpose", &self.purpose)
            .field("token_hash", &"[REDACTED]")
            .field("issued_at_epoch", &self.issued_at_epoch)
            .field("expires_at_epoch", &self.expires_at_epoch)
            .field("consumed_at_epoch", &self.consumed_at_epoch)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeTokenRejection {
    Expired,
    AlreadyConsumed,
    WrongPurpose,
    HashMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeTokenVerification {
    Accepted,
    Rejected(OneTimeTokenRejection),
}

pub fn verify_and_consume(
    record: &mut OneTimeTokenRecord,
    provided_token: &str,
    expected_purpose: &OneTimeTokenPurpose,
    now_epoch: i64,
) -> OneTimeTokenVerification {
    if record.purpose != expected_purpose.as_str() {
        return OneTimeTokenVerification::Rejected(OneTimeTokenRejection::WrongPurpose);
    }
    if record.consumed_at_epoch.is_some() {
        return OneTimeTokenVerification::Rejected(OneTimeTokenRejection::AlreadyConsumed);
    }
    if now_epoch >= record.expires_at_epoch {
        return OneTimeTokenVerification::Rejected(OneTimeTokenRejection::Expired);
    }

    let provided_hash = hash_token(provided_token);
    if !constant_time_eq(provided_hash.as_bytes(), record.token_hash.as_bytes()) {
        return OneTimeTokenVerification::Rejected(OneTimeTokenRejection::HashMismatch);
    }

    record.consumed_at_epoch = Some(now_epoch);
    OneTimeTokenVerification::Accepted
}
