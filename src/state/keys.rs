//! Purpose-bound HMAC keys derived from the Klaxond session secret.
//!
//! Before 0.23 the session secret was used directly as the HMAC key for five
//! unrelated purposes, so a tag minted for one could verify as another (an
//! emergency acknowledgement token verified as an inhibition acknowledgement
//! for the alert name `"ack"`). Every purpose now uses its own HKDF sub-key
//! (`auth_modules::keys`), selected by a [`KeyLabel`].
//!
//! The 0.23 transition, which still verified raw-secret tags (acknowledgement
//! links, legacy stateless cookies, rate-limit records, in-flight session
//! rotations) until they expired, was removed in the next release: the raw
//! secret no longer verifies anything.

use anyhow::{Result, anyhow};
use auth_modules::keys::{KeyGeneration, KeyLabel, KeyRing, MasterKey};
use std::fmt;

/// Deterministic successor token of a rotated persistent session.
pub const SESSION_ROTATION: KeyLabel = KeyLabel::new("klaxond/session-rotation/v1");
/// Keyed hash of the account dimension of the persistent auth rate limit.
pub const AUTH_RATE_ACCOUNT: KeyLabel = KeyLabel::new("klaxond/auth-rate-account/v1");
/// Emergency acknowledgement links (`{"r","e","a":"ack"}`).
pub const EMERGENCY_ACK: KeyLabel = KeyLabel::new("klaxond/emergency-ack/v1");
/// Inhibition acknowledgement links sent with ntfy actions (`{"a","t","e"}`).
pub const INHIBITION_ACK: KeyLabel = KeyLabel::new("klaxond/inhibition-ack/v1");

#[derive(Clone)]
pub struct ServiceKeys {
    ring: KeyRing,
}

impl ServiceKeys {
    /// Builds the key ring from the session secret. The secret must be at
    /// least 32 bytes and must not repeat a single byte.
    pub fn from_secret(secret: Vec<u8>) -> Result<Self> {
        let master = MasterKey::from_bytes(secret).map_err(|err| {
            anyhow!(
                "session secret rejected: {err}; set AUTH_SESSION_SECRET (or [auth].session_secret) \
                 to at least 32 random bytes, e.g. `openssl rand -base64 32`, or unset it to use \
                 the generated auth-session.key"
            )
        })?;
        Ok(Self {
            ring: KeyRing::new(master),
        })
    }

    /// Lowercase hex HMAC-SHA256 of `message` with the current sub-key.
    pub fn sign_hex(&self, label: KeyLabel, message: &[u8]) -> String {
        hex::encode(self.ring.sign(label, message))
    }

    /// Verifies a hex tag under `label`'s derived sub-key.
    pub fn verify_hex(
        &self,
        label: KeyLabel,
        message: &[u8],
        tag_hex: &str,
    ) -> Option<KeyGeneration> {
        let tag = hex::decode(tag_hex).ok()?;
        self.ring.verify(label, message, &tag)
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
        assert!(keys.verify_hex(SESSION_ROTATION, b"body", &tag).is_none());
        assert_ne!(tag, hmac_hex(&secret(), b"body"));
    }

    #[test]
    fn raw_secret_tags_no_longer_verify_under_any_label() {
        let keys = ServiceKeys::from_secret(secret()).unwrap();
        let raw = hmac_hex(&secret(), b"body");
        for label in [
            SESSION_ROTATION,
            AUTH_RATE_ACCOUNT,
            EMERGENCY_ACK,
            INHIBITION_ACK,
        ] {
            assert!(keys.verify_hex(label, b"body", &raw).is_none());
        }
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
