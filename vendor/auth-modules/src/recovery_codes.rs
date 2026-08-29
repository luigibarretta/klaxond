use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::secrets::constant_time_eq;

const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCodePolicy {
    pub count: usize,
    pub groups: usize,
    pub group_len: usize,
}

impl RecoveryCodePolicy {
    pub fn new(count: usize, groups: usize, group_len: usize) -> Self {
        Self {
            count: count.max(1),
            groups: groups.max(1),
            group_len: group_len.max(4),
        }
    }

    pub fn gold_standard() -> Self {
        Self::new(10, 4, 4)
    }

    pub fn code_chars(self) -> usize {
        self.groups * self.group_len
    }
}

impl Default for RecoveryCodePolicy {
    fn default() -> Self {
        Self::gold_standard()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCodeSet {
    pub plaintext_codes: Vec<String>,
    pub hashes: Vec<RecoveryCodeHash>,
}

impl fmt::Debug for RecoveryCodeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCodeSet")
            .field("plaintext_codes", &"[REDACTED]")
            .field("hashes", &self.hashes)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCodeHash {
    pub hash: String,
    pub used_at_epoch: Option<i64>,
}

impl fmt::Debug for RecoveryCodeHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCodeHash")
            .field("hash", &"[REDACTED]")
            .field("used_at_epoch", &self.used_at_epoch)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCodeVerification {
    Accepted,
    Rejected,
    AlreadyUsed,
}

pub fn generate_recovery_codes(policy: RecoveryCodePolicy) -> RecoveryCodeSet {
    let plaintext_codes = (0..policy.count)
        .map(|_| generate_recovery_code(policy))
        .collect::<Vec<_>>();
    let hashes = plaintext_codes
        .iter()
        .map(|code| RecoveryCodeHash {
            hash: hash_recovery_code(code),
            used_at_epoch: None,
        })
        .collect();

    RecoveryCodeSet {
        plaintext_codes,
        hashes,
    }
}

pub fn generate_recovery_code(policy: RecoveryCodePolicy) -> String {
    let mut bytes = vec![0_u8; policy.code_chars()];
    OsRng.fill_bytes(&mut bytes);
    let chars = bytes
        .into_iter()
        .map(|byte| RECOVERY_ALPHABET[usize::from(byte & 31)] as char)
        .collect::<Vec<_>>();

    chars
        .chunks(policy.group_len)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn hash_recovery_code(code: &str) -> String {
    let normalized = normalize_recovery_code(code);
    let digest = Sha256::digest(normalized.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn verify_recovery_code_hash(provided_code: &str, stored_hash: &str) -> bool {
    let provided_hash = hash_recovery_code(provided_code);
    constant_time_eq(provided_hash.as_bytes(), stored_hash.as_bytes())
}

pub fn consume_recovery_code(
    hashes: &mut [RecoveryCodeHash],
    provided_code: &str,
    now_epoch: i64,
) -> RecoveryCodeVerification {
    let provided_hash = hash_recovery_code(provided_code);
    let mut matched_used_index = None;
    let mut matched_unused_index = None;

    for (index, stored) in hashes.iter().enumerate() {
        if constant_time_eq(provided_hash.as_bytes(), stored.hash.as_bytes()) {
            if stored.used_at_epoch.is_some() {
                matched_used_index = Some(index);
            } else {
                matched_unused_index = Some(index);
            }
        }
    }

    if let Some(index) = matched_unused_index {
        hashes[index].used_at_epoch = Some(now_epoch);
        return RecoveryCodeVerification::Accepted;
    }
    if matched_used_index.is_some() {
        return RecoveryCodeVerification::AlreadyUsed;
    }
    RecoveryCodeVerification::Rejected
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_have_gold_shape_and_hashes() {
        let set = generate_recovery_codes(RecoveryCodePolicy::gold_standard());

        assert_eq!(set.plaintext_codes.len(), 10);
        assert_eq!(set.hashes.len(), 10);
        for code in &set.plaintext_codes {
            assert_eq!(code.len(), 19);
            assert_eq!(code.chars().filter(|ch| *ch == '-').count(), 3);
        }
        assert_ne!(set.plaintext_codes[0], set.hashes[0].hash);
    }

    #[test]
    fn normalization_allows_spaces_hyphens_and_case_changes() {
        let hash = hash_recovery_code("ABCD-EFGH-JKLM-NPQR");

        assert!(verify_recovery_code_hash("abcd efgh jklm npqr", &hash));
    }

    #[test]
    fn recovery_code_can_be_consumed_once() {
        let mut set = generate_recovery_codes(RecoveryCodePolicy::new(1, 2, 4));
        let code = set.plaintext_codes[0].clone();

        assert_eq!(
            consume_recovery_code(&mut set.hashes, &code, 100),
            RecoveryCodeVerification::Accepted
        );
        assert_eq!(
            consume_recovery_code(&mut set.hashes, &code, 101),
            RecoveryCodeVerification::AlreadyUsed
        );
        assert_eq!(
            consume_recovery_code(&mut set.hashes, "AAAA-BBBB", 102),
            RecoveryCodeVerification::Rejected
        );
    }

    #[test]
    fn recovery_code_debug_redacts_plaintext_and_hashes() {
        let set = generate_recovery_codes(RecoveryCodePolicy::new(1, 2, 4));
        let debug = format!("{set:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&set.plaintext_codes[0]));
        assert!(!debug.contains(&set.hashes[0].hash));
    }
}
