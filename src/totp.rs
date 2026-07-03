//! Local TOTP/HOTP helpers for the basic-auth MFA flow.

use crate::util::random_bytes;
use hmac::{Hmac, Mac};
use sha1::Sha1;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_STEP_SECONDS: i64 = 30;
const TOTP_ALLOWED_SKEW_STEPS: std::ops::RangeInclusive<i64> = -1..=1;

pub fn generate_secret() -> String {
    base32_encode(&random_bytes::<20>())
}

pub fn otpauth_uri(label: &str, issuer: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={}",
        urlencoding::encode(label),
        secret,
        urlencoding::encode(issuer),
        TOTP_STEP_SECONDS
    )
}

pub fn is_valid_secret(secret: &str) -> bool {
    base32_decode(secret).is_some()
}

pub fn verify_code(secret: &str, code: &str, now: i64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.as_bytes().iter().all(u8::is_ascii_digit) {
        return false;
    }
    let Ok(expected) = code.parse::<u32>() else {
        return false;
    };
    let Some(secret) = base32_decode(secret) else {
        return false;
    };
    let counter = now.max(0) / TOTP_STEP_SECONDS;
    TOTP_ALLOWED_SKEW_STEPS.clone().any(|skew| {
        let step = counter + skew;
        step >= 0 && hotp(&secret, step as u64).is_some_and(|value| value == expected)
    })
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[idx] as char);
    }
    output
}

fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in value.chars().filter(|ch| !ch.is_whitespace()) {
        if ch == '=' {
            break;
        }
        let ch = ch.to_ascii_uppercase();
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        while bits >= 8 {
            output.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    (!output.is_empty()).then_some(output)
}

fn hotp(secret: &[u8], counter: u64) -> Option<u32> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = usize::from(out[19] & 0x0f);
    let binary = (u32::from(out[offset] & 0x7f) << 24)
        | (u32::from(out[offset + 1]) << 16)
        | (u32::from(out[offset + 2]) << 8)
        | u32::from(out[offset + 3]);
    Some(binary % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips_secret_bytes() {
        let raw = b"12345678901234567890";
        let encoded = base32_encode(raw);

        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&encoded).unwrap(), raw);
    }

    #[test]
    fn hotp_matches_rfc_4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];

        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64), Some(code));
        }
    }

    #[test]
    fn totp_verification_accepts_current_and_adjacent_steps() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        assert!(verify_code(secret, "755224", 30));
        assert!(verify_code(secret, "287082", 30));
        assert!(verify_code(secret, "359152", 30));
        assert!(!verify_code(secret, "969429", 30));
        assert!(!verify_code(secret, "not-a-code", 30));
    }
}
