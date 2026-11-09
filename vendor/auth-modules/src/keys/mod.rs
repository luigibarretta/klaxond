//! Domain-separated sub-key derivation from one master secret.
//!
//! Services that need several MAC or encryption keys (session cookies,
//! acknowledgement links, sealed settings) derive each one from a single
//! [`MasterKey`] with HKDF-SHA256 and a namespaced [`KeyLabel`] such as
//! `"klaxond/alert-ack/v1"`. A key derived for one purpose can therefore never
//! verify data produced for another, and rotating a purpose only means bumping
//! its label version. [`KeyRing`] keeps previous master secrets (or legacy raw
//! secrets that were used directly) for verification during rotation.
//!
//! Loading the master secret, storing it, and choosing labels stay in the
//! application. The crate has no zeroize dependency: secret buffers are
//! wrapped in [`crate::secrets::Redacted`] so they never reach `Debug` output,
//! but they are not wiped on drop.

mod hkdf;
mod ring;

use std::fmt;

use crate::secrets::{constant_time_eq, Redacted};

pub use ring::{legacy_hmac_sha256, KeyGeneration, KeyRing};

/// Minimum master secret length in bytes.
pub const MIN_MASTER_KEY_BYTES: usize = 32;
/// Length of every derived sub-key in bytes.
pub const SUBKEY_BYTES: usize = 32;
/// Maximum accepted label length in bytes.
pub const MAX_LABEL_BYTES: usize = 128;

/// Fixed HKDF salt binding derivations to this crate's scheme version.
const HKDF_SALT: &[u8] = b"auth-modules/keys/hkdf-sha256/v1";

/// Root secret from which purpose-specific sub-keys are derived.
#[derive(Clone)]
pub struct MasterKey(Redacted<Vec<u8>>);

impl MasterKey {
    /// Accepts at least [`MIN_MASTER_KEY_BYTES`] bytes. Material made of one
    /// repeated byte (for example an all-zero placeholder) is rejected.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, KeyError> {
        let bytes = bytes.into();
        if bytes.len() < MIN_MASTER_KEY_BYTES {
            return Err(KeyError::new("master key must be at least 32 bytes"));
        }
        if bytes.iter().all(|byte| *byte == bytes[0]) {
            return Err(KeyError::new("master key must not repeat a single byte"));
        }
        Ok(Self(Redacted::new(bytes)))
    }

    /// Derives the 32-byte sub-key for `label`.
    pub fn derive(&self, label: KeyLabel) -> SubKey {
        let mut bytes = [0_u8; SUBKEY_BYTES];
        hkdf::hkdf_sha256(
            HKDF_SALT,
            self.0.expose_secret(),
            label.as_str().as_bytes(),
            &mut bytes,
        );
        SubKey { label, bytes }
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// A namespaced, versioned derivation label: at least three `/`-separated
/// segments of `[a-z0-9._-]`, the last of which is `v<digits>`, for example
/// `"app/purpose/v1"`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyLabel(&'static str);

impl KeyLabel {
    /// Validates at compile time when used in a `const` item:
    /// `const SESSION: KeyLabel = KeyLabel::new("app/session/v1");`.
    /// Panics on an invalid label when called at runtime; use
    /// [`KeyLabel::try_new`] for labels that are not literals.
    pub const fn new(label: &'static str) -> Self {
        if !label_is_valid(label) {
            panic!("invalid key label: expected namespaced \"app/purpose/vN\"");
        }
        Self(label)
    }

    pub fn try_new(label: &'static str) -> Result<Self, KeyError> {
        if label_is_valid(label) {
            Ok(Self(label))
        } else {
            Err(KeyError::new(
                "invalid key label: expected namespaced \"app/purpose/vN\"",
            ))
        }
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

const fn label_is_valid(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LABEL_BYTES {
        return false;
    }
    let mut segments = 1;
    let mut segment_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'/' {
            if index == segment_start {
                return false;
            }
            segments += 1;
            segment_start = index + 1;
        } else if !(byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_' | b'.'))
        {
            return false;
        }
        index += 1;
    }
    segments >= 3 && version_segment_is_valid(bytes, segment_start)
}

const fn version_segment_is_valid(bytes: &[u8], start: usize) -> bool {
    if start + 1 >= bytes.len() || bytes[start] != b'v' {
        return false;
    }
    let mut index = start + 1;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
        index += 1;
    }
    true
}

/// A derived 32-byte key bound to one label.
#[derive(Clone)]
pub struct SubKey {
    label: KeyLabel,
    bytes: [u8; SUBKEY_BYTES],
}

impl SubKey {
    pub fn label(&self) -> KeyLabel {
        self.label
    }

    /// Raw key bytes, for use with an encryption or MAC primitive.
    pub fn expose_secret(&self) -> &[u8; SUBKEY_BYTES] {
        &self.bytes
    }

    pub fn hmac_sha256(&self, message: &[u8]) -> [u8; 32] {
        hkdf::hmac_sha256(&self.bytes, message)
    }

    /// Constant-time verification of an HMAC-SHA256 tag.
    pub fn verify_hmac_sha256(&self, message: &[u8], tag: &[u8]) -> bool {
        constant_time_eq(&self.hmac_sha256(message), tag)
    }
}

impl fmt::Debug for SubKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubKey")
            .field("label", &self.label.as_str())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Invalid key material or label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyError {
    message: &'static str,
}

impl KeyError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for KeyError {}

#[cfg(test)]
mod tests;
