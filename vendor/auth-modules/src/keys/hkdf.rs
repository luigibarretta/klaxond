//! HKDF-SHA256 (RFC 5869) on top of the `hmac` and `sha2` crates already in
//! the dependency graph, so the crate does not need a separate `hkdf`
//! dependency. Verified against the RFC 5869 SHA-256 test vectors.

use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub(super) const HASH_LEN: usize = 32;
const BLOCK_LEN: usize = 64;

/// Builds an HMAC instance without a fallible constructor: RFC 2104 hashes
/// keys longer than one block and zero-pads shorter ones, which is exactly
/// what `Mac::new_from_slice` does internally.
fn keyed(key: &[u8]) -> HmacSha256 {
    let mut block = [0_u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block[..HASH_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    <HmacSha256 as KeyInit>::new(GenericArray::from_slice(&block))
}

pub(super) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = keyed(key);
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Fills `okm` with HKDF-Extract-then-Expand output. `okm` must not exceed
/// 255 hash blocks; the callers in this crate use fixed small lengths.
pub(super) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    assert!(okm.len() <= 255 * HASH_LEN, "HKDF output too long");
    let prk = hmac_sha256(salt, ikm);
    let mut previous: Option<[u8; HASH_LEN]> = None;
    for (chunk, counter) in okm.chunks_mut(HASH_LEN).zip(1_u8..=255) {
        let mut mac = keyed(&prk);
        if let Some(block) = previous {
            mac.update(&block);
        }
        mac.update(info);
        mac.update(&[counter]);
        let block: [u8; HASH_LEN] = mac.finalize().into_bytes().into();
        chunk.copy_from_slice(&block[..chunk.len()]);
        previous = Some(block);
    }
}
