use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

use crate::secrets::constant_time_eq as constant_time_bytes_eq;

pub const DEFAULT_SECRET_BYTES: usize = 20;
pub const DEFAULT_STEP_SECONDS: i64 = 30;
pub const DEFAULT_ALLOWED_SKEW_STEPS: i64 = 1;
pub const DEFAULT_DIGITS: u32 = 6;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpConfig {
    pub step_seconds: i64,
    pub allowed_skew_steps: i64,
    pub digits: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            step_seconds: DEFAULT_STEP_SECONDS,
            allowed_skew_steps: DEFAULT_ALLOWED_SKEW_STEPS,
            digits: DEFAULT_DIGITS,
        }
    }
}

impl TotpConfig {
    pub fn is_valid(self) -> bool {
        (1..=300).contains(&self.step_seconds)
            && (0..=2).contains(&self.allowed_skew_steps)
            && matches!(self.digits, 6 | 8)
    }
}

pub fn generate_secret() -> String {
    let mut bytes = [0_u8; DEFAULT_SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

pub fn is_valid_secret(secret: &str) -> bool {
    base32_decode(secret).is_some()
}

pub fn verify_code(secret: &str, code: &str, timestamp: i64) -> bool {
    verify_code_counter(secret, code, timestamp).is_some()
}

pub fn verify_code_with_config(
    secret: &str,
    code: &str,
    timestamp: i64,
    config: TotpConfig,
) -> bool {
    verify_code_counter_with_config(secret, code, timestamp, config).is_some()
}

/// Returns the accepted HOTP counter so callers can atomically reject TOTP replay.
pub fn verify_code_counter(secret: &str, code: &str, timestamp: i64) -> Option<u64> {
    verify_code_counter_with_config(secret, code, timestamp, TotpConfig::default())
}

pub fn verify_code_counter_with_config(
    secret: &str,
    code: &str,
    timestamp: i64,
    config: TotpConfig,
) -> Option<u64> {
    if !config.is_valid() {
        return None;
    }
    let code = normalized_code(code);
    if code.len() != config.digits as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let secret = base32_decode(secret)?;
    if secret.len() < DEFAULT_SECRET_BYTES {
        return None;
    }
    let counter = timestamp.max(0) / config.step_seconds;
    (-config.allowed_skew_steps..=config.allowed_skew_steps).find_map(|offset| {
        let step = counter.checked_add(offset)?;
        let step = u64::try_from(step).ok()?;
        hotp_code(&secret, step, config.digits)
            .filter(|candidate| constant_time_eq(candidate, &code))
            .map(|_| step)
    })
}

pub fn hotp_code(secret: &[u8], counter: u64, digits: u32) -> Option<String> {
    let modulo = 10_u32.checked_pow(digits)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = usize::from(out[19] & 0x0f);
    let binary = (u32::from(out[offset] & 0x7f) << 24)
        | (u32::from(out[offset + 1]) << 16)
        | (u32::from(out[offset + 2]) << 8)
        | u32::from(out[offset + 3]);
    Some(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}

pub fn current_step(timestamp: i64) -> i64 {
    timestamp.max(0) / DEFAULT_STEP_SECONDS
}

pub fn otpauth_uri(label: &str, issuer: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={}",
        percent_encode(label),
        secret,
        percent_encode(issuer),
        DEFAULT_STEP_SECONDS
    )
}

pub fn otpauth_uri_with_issuer_prefix(account_name: &str, issuer: &str, secret: &str) -> String {
    otpauth_uri(&format!("{issuer}:{account_name}"), issuer, secret)
}

pub fn base32_encode(bytes: &[u8]) -> String {
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

pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in value
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '\t' | '\r' | '\n' | '-'))
    {
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

pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn normalized_code(code: &str) -> String {
    code.trim().replace(' ', "")
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    constant_time_bytes_eq(left.as_bytes(), right.as_bytes())
}

#[cfg(test)]
mod tests;
