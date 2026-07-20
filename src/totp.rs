//! Local TOTP/HOTP helpers for the basic-auth MFA flow.

pub fn generate_secret() -> String {
    auth_modules::totp::generate_secret()
}

pub fn otpauth_uri(label: &str, issuer: &str, secret: &str) -> String {
    auth_modules::totp::otpauth_uri(label, issuer, secret)
}

pub fn is_valid_secret(secret: &str) -> bool {
    auth_modules::totp::is_valid_secret(secret)
}

pub fn verify_code(secret: &str, code: &str, now: i64) -> bool {
    auth_modules::totp::verify_code(secret, code, now)
}

pub fn verify_code_counter(secret: &str, code: &str, now: i64) -> Option<u64> {
    auth_modules::totp::verify_code_counter(secret, code, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_valid_base32() {
        let secret = generate_secret();

        assert!(is_valid_secret(&secret));
    }

    #[test]
    fn otpauth_uri_matches_existing_shape() {
        let uri = otpauth_uri("klaxond:luigi", "klaxond", "SECRET");

        assert_eq!(
            uri,
            "otpauth://totp/klaxond%3Aluigi?secret=SECRET&issuer=klaxond&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn totp_verification_accepts_current_and_adjacent_steps() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let step_seconds = auth_modules::totp::DEFAULT_STEP_SECONDS;

        assert!(verify_code(secret, "755224", step_seconds));
        assert!(verify_code(secret, "287082", step_seconds));
        assert!(verify_code(secret, "359152", step_seconds));
        assert!(!verify_code(secret, "969429", step_seconds));
        assert!(!verify_code(secret, "not-a-code", step_seconds));
        assert_eq!(verify_code_counter(secret, "287082", step_seconds), Some(1));
    }
}
