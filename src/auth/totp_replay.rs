use crate::config::save_auth;
use crate::state::AppState;
use crate::totp;
use crate::util::now_epoch_i64;

pub(super) fn consume_basic_totp(state: &AppState, code: &str) -> Result<bool, String> {
    state.with_config_write_lock(|| {
        let mut cfg = state.cfg();
        let basic = &mut cfg.auth.basic;
        let Some(counter) = totp::verify_code_counter(&basic.totp_secret, code, now_epoch_i64())
        else {
            return Ok(false);
        };
        if basic.totp_last_counter.is_some_and(|last| counter <= last) {
            return Ok(false);
        }
        basic.totp_last_counter = Some(counter);
        save_auth(&state.paths, &cfg.auth).map_err(|err| err.to_string())?;
        state.replace_config(cfg);
        Ok(true)
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::temp_paths;
    use auth_modules::totp::{base32_decode, current_step, hotp_code};
    use tempfile::TempDir;

    #[test]
    fn basic_totp_counter_is_consumed_once() {
        let tmp = TempDir::new().expect("tempdir");
        let state = AppState::new(temp_paths(&tmp)).expect("state");
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let now = now_epoch_i64();
        let counter = u64::try_from(current_step(now)).expect("current counter");
        let code = hotp_code(
            &base32_decode(secret).expect("base32 secret"),
            counter,
            auth_modules::totp::DEFAULT_DIGITS,
        )
        .expect("TOTP code");
        let mut cfg = state.cfg();
        cfg.auth.basic.totp_enabled = true;
        cfg.auth.basic.totp_secret = secret.to_string();
        state.replace_config(cfg);

        assert!(consume_basic_totp(&state, &code).expect("first consume"));
        assert!(!consume_basic_totp(&state, &code).expect("replay consume"));
        assert_eq!(state.cfg().auth.basic.totp_last_counter, Some(counter));
    }
}
