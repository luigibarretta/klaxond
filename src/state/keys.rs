//! Purpose-bound HMAC keys derived from the Klaxond session secret.
//!
//! Before 0.23 the session secret was used directly as the HMAC key for five
//! unrelated purposes, so a tag minted for one could verify as another (an
//! emergency acknowledgement token verified as an inhibition acknowledgement
//! for the alert name `"ack"`). Every purpose now uses its own HKDF sub-key
//! (`auth_modules::keys`), selected by a [`KeyLabel`].
//!
//! Transition: tags minted before the upgrade (acknowledgement links already
//! sent through ntfy, legacy stateless cookies, account rate-limit records,
//! in-flight session rotations) were produced with the raw secret. The raw
//! secret is kept as a legacy key, scoped to the verifying labels whose old
//! code used it, until those artefacts have expired. Remove
//! [`LEGACY_RAW_VERIFY_LABELS`] and [`ServiceKeys::legacy_hex`] in the release
//! after the longest acknowledgement TTL configured in production has passed.

use anyhow::{Result, anyhow};
use auth_modules::keys::{KeyGeneration, KeyLabel, KeyRing, MasterKey, legacy_hmac_sha256};
use auth_modules::secrets::Redacted;
use std::fmt;

/// Legacy stateless session cookies (verification only; none are minted).
pub const LEGACY_SESSION_COOKIE: KeyLabel = KeyLabel::new("klaxond/legacy-session-cookie/v1");
/// Deterministic successor token of a rotated persistent session.
pub const SESSION_ROTATION: KeyLabel = KeyLabel::new("klaxond/session-rotation/v1");
/// Keyed hash of the account dimension of the persistent auth rate limit.
pub const AUTH_RATE_ACCOUNT: KeyLabel = KeyLabel::new("klaxond/auth-rate-account/v1");
/// Emergency acknowledgement links (`{"r","e","a":"ack"}`).
pub const EMERGENCY_ACK: KeyLabel = KeyLabel::new("klaxond/emergency-ack/v1");
/// Inhibition acknowledgement links sent with ntfy actions (`{"a","t","e"}`).
pub const INHIBITION_ACK: KeyLabel = KeyLabel::new("klaxond/inhibition-ack/v1");

/// Labels under which the raw pre-0.23 secret still verifies. The payload
/// parsers of these three formats reject each other's shapes, so a legacy tag
/// cannot cross purposes even inside this set.
pub const LEGACY_RAW_VERIFY_LABELS: [KeyLabel; 3] =
    [LEGACY_SESSION_COOKIE, EMERGENCY_ACK, INHIBITION_ACK];

#[derive(Clone)]
pub struct ServiceKeys {
    ring: KeyRing,
    legacy_raw: Redacted<Vec<u8>>,
}

impl ServiceKeys {
    /// Builds the key ring from the session secret. The secret must be at
    /// least 32 bytes and must not repeat a single byte.
    pub fn from_secret(secret: Vec<u8>) -> Result<Self> {
        let master = MasterKey::from_bytes(secret.clone()).map_err(|err| {
            anyhow!(
                "session secret rejected: {err}; set AUTH_SESSION_SECRET (or [auth].session_secret) \
                 to at least 32 random bytes, e.g. `openssl rand -base64 32`, or unset it to use \
                 the generated auth-session.key"
            )
        })?;
        let ring = KeyRing::new(master)
            .with_legacy_raw(secret.clone(), &LEGACY_RAW_VERIFY_LABELS)
            .map_err(|err| anyhow!("legacy session secret rejected: {err}"))?;
        Ok(Self {
            ring,
            legacy_raw: Redacted::new(secret),
        })
    }

    /// Lowercase hex HMAC-SHA256 of `message` with the current sub-key.
    pub fn sign_hex(&self, label: KeyLabel, message: &[u8]) -> String {
        hex::encode(self.ring.sign(label, message))
    }

    /// Verifies a hex tag under `label`; legacy raw tags verify only for the
    /// labels in [`LEGACY_RAW_VERIFY_LABELS`].
    pub fn verify_hex(
        &self,
        label: KeyLabel,
        message: &[u8],
        tag_hex: &str,
    ) -> Option<KeyGeneration> {
        let tag = hex::decode(tag_hex).ok()?;
        self.ring.verify(label, message, &tag)
    }

    /// The pre-0.23 raw-secret HMAC of `message`, for recomputed values
    /// (rate-limit hashes, rotation successors) that must still be found
    /// during the transition. Never use it to mint anything new.
    pub fn legacy_hex(&self, message: &[u8]) -> String {
        hex::encode(legacy_hmac_sha256(self.legacy_raw.expose_secret(), message))
    }
}

impl fmt::Debug for ServiceKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceKeys([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hmac_hex;

    fn secret() -> Vec<u8> {
        (0_u8..32).collect()
    }

    #[test]
    fn short_or_constant_secrets_are_rejected() {
        assert!(ServiceKeys::from_secret(b"toml-session-secret".to_vec()).is_err());
        assert!(ServiceKeys::from_secret(vec![7_u8; 64]).is_err());
        assert!(ServiceKeys::from_secret(secret()).is_ok());
    }

    #[test]
    fn purposes_use_independent_keys() {
        let keys = ServiceKeys::from_secret(secret()).unwrap();
        let tag = keys.sign_hex(EMERGENCY_ACK, b"body");
        assert!(keys.verify_hex(EMERGENCY_ACK, b"body", &tag).is_some());
        assert!(keys.verify_hex(INHIBITION_ACK, b"body", &tag).is_none());
        assert!(
            keys.verify_hex(LEGACY_SESSION_COOKIE, b"body", &tag)
                .is_none()
        );
        assert_ne!(tag, hmac_hex(&secret(), b"body"));
    }

    #[test]
    fn raw_legacy_tags_verify_only_under_scoped_labels() {
        let keys = ServiceKeys::from_secret(secret()).unwrap();
        let legacy = hmac_hex(&secret(), b"body");
        for label in LEGACY_RAW_VERIFY_LABELS {
            assert_eq!(
                keys.verify_hex(label, b"body", &legacy),
                Some(KeyGeneration::Legacy(0))
            );
        }
        assert!(
            keys.verify_hex(SESSION_ROTATION, b"body", &legacy)
                .is_none()
        );
        assert!(
            keys.verify_hex(AUTH_RATE_ACCOUNT, b"body", &legacy)
                .is_none()
        );
        assert_eq!(keys.legacy_hex(b"body"), legacy);
    }

    #[test]
    fn malformed_hex_tags_are_rejected() {
        let keys = ServiceKeys::from_secret(secret()).unwrap();
        assert!(keys.verify_hex(EMERGENCY_ACK, b"body", "zz").is_none());
        assert!(keys.verify_hex(EMERGENCY_ACK, b"body", "").is_none());
    }

    #[test]
    fn debug_output_is_redacted() {
        let keys = ServiceKeys::from_secret(secret()).unwrap();
        assert_eq!(format!("{keys:?}"), "ServiceKeys([REDACTED])");
    }
}
