use std::fmt;

use super::hkdf::hmac_sha256;
use super::{KeyError, KeyLabel, MasterKey, SubKey};
use crate::secrets::{constant_time_eq, Redacted};

/// Which key generation verified a tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyGeneration {
    Current,
    /// Index into the legacy keys, in the order they were added.
    Legacy(usize),
}

#[derive(Clone)]
enum LegacyKey {
    /// A previous master secret; sub-keys are derived with the same label.
    Master(MasterKey),
    /// A secret that was used directly as an HMAC key before derivation was
    /// introduced. It verifies only under the labels it is scoped to, so a
    /// legacy tag for one purpose cannot be replayed under another.
    Raw {
        secret: Redacted<Vec<u8>>,
        labels: Vec<KeyLabel>,
    },
}

/// The current master key plus legacy keys accepted only for verification.
///
/// New tags are always produced with the current key. Callers should
/// re-issue data verified by a [`KeyGeneration::Legacy`] key and remove the
/// legacy entry once no such data can remain.
#[derive(Clone)]
pub struct KeyRing {
    current: MasterKey,
    legacy: Vec<LegacyKey>,
}

impl KeyRing {
    pub fn new(current: MasterKey) -> Self {
        Self {
            current,
            legacy: Vec::new(),
        }
    }

    pub fn with_legacy_master(mut self, previous: MasterKey) -> Self {
        self.legacy.push(LegacyKey::Master(previous));
        self
    }

    /// Accepts a non-empty secret that was previously used as a raw HMAC key,
    /// valid only for the purposes in `labels` (the labels that replaced the
    /// raw usages). `labels` must not be empty.
    pub fn with_legacy_raw(
        mut self,
        secret: Vec<u8>,
        labels: &[KeyLabel],
    ) -> Result<Self, KeyError> {
        if secret.is_empty() {
            return Err(KeyError::new("legacy key must not be empty"));
        }
        if labels.is_empty() {
            return Err(KeyError::new("legacy raw key must be scoped to labels"));
        }
        self.legacy.push(LegacyKey::Raw {
            secret: Redacted::new(secret),
            labels: labels.to_vec(),
        });
        Ok(self)
    }

    pub fn current(&self, label: KeyLabel) -> SubKey {
        self.current.derive(label)
    }

    /// HMAC-SHA256 with the current sub-key for `label`.
    pub fn sign(&self, label: KeyLabel, message: &[u8]) -> [u8; 32] {
        self.current(label).hmac_sha256(message)
    }

    /// Verifies `tag` against the current key, then every legacy key, and
    /// reports which generation matched.
    pub fn verify(&self, label: KeyLabel, message: &[u8], tag: &[u8]) -> Option<KeyGeneration> {
        if self.current(label).verify_hmac_sha256(message, tag) {
            return Some(KeyGeneration::Current);
        }
        self.legacy
            .iter()
            .position(|legacy| match legacy {
                LegacyKey::Master(master) => master.derive(label).verify_hmac_sha256(message, tag),
                LegacyKey::Raw { secret, labels } => {
                    labels.contains(&label)
                        && constant_time_eq(
                            &legacy_hmac_sha256(secret.expose_secret(), message),
                            tag,
                        )
                }
            })
            .map(KeyGeneration::Legacy)
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRing")
            .field("current", &self.current)
            .field("legacy_keys", &self.legacy.len())
            .finish()
    }
}

/// HMAC-SHA256 with a raw, non-derived key. Use it only to reproduce tags
/// created before a service adopted [`MasterKey::derive`]; new code should
/// derive a labelled [`SubKey`] instead.
pub fn legacy_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac_sha256(key, message)
}
