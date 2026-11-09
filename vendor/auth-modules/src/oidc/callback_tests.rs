use super::callback::verify_callback_state;
use super::{CallbackParams, OidcClientConfig};

const VERIFIER: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

fn params<'a>(state: &'a str, expected_state: &'a str) -> CallbackParams<'a> {
    CallbackParams {
        code: "authorization-code",
        state,
        expected_state,
        nonce: "nonce-value",
        pkce_verifier: VERIFIER,
    }
}

/// An issuer nobody listens on: reaching discovery would produce a network
/// error instead of the state error the tests expect.
fn unreachable_config() -> OidcClientConfig {
    OidcClientConfig::new(
        "https://127.0.0.1:9/application/o/test/",
        "client",
        Some("secret".to_string()),
        "https://app.example.test/api/auth/callback",
        vec!["openid".to_string()],
    )
}

fn assert_state_error(result: Result<impl Sized, super::OidcError>) {
    let error = result.err().expect("state mismatch must fail").to_string();
    assert!(error.contains("state"), "unexpected error: {error}");
    assert!(!error.contains("discovery"), "network was reached: {error}");
}

#[test]
fn matching_state_is_accepted() {
    assert!(verify_callback_state(&params("state-123", "state-123")).is_ok());
}

#[test]
fn mismatched_empty_or_truncated_state_is_rejected() {
    for (state, expected) in [
        ("state-123", "state-124"),
        ("state-12", "state-123"),
        ("state-1234", "state-123"),
        ("", "state-123"),
        ("", ""),
        ("   ", "   "),
    ] {
        assert!(
            verify_callback_state(&params(state, expected)).is_err(),
            "{state:?} vs {expected:?}"
        );
    }
}

#[test]
fn empty_code_is_rejected_before_exchange() {
    let mut callback = params("state-123", "state-123");
    callback.code = "";
    assert!(verify_callback_state(&callback).is_err());
}

#[test]
fn callback_params_debug_redacts_every_value() {
    let callback = params("csrf-state", "csrf-state");
    let debug = format!("{callback:?}");
    for secret in ["authorization-code", "csrf-state", "nonce-value", VERIFIER] {
        assert!(!debug.contains(secret), "{secret} leaked: {debug}");
    }
}

#[cfg(feature = "oidc-blocking")]
#[test]
fn blocking_exchange_callback_checks_state_before_discovery() {
    let config = unreachable_config();
    assert_state_error(super::blocking::exchange_callback(
        &config,
        &params("attacker-state", "victim-state"),
    ));
}

#[cfg(feature = "oidc-async")]
#[test]
fn async_exchange_callback_checks_state_before_discovery() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let config = unreachable_config();
    let callback = params("attacker-state", "victim-state");
    let future = super::async_client::exchange_callback(&config, &callback);
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    // Without a runtime any network I/O would stay pending or panic, so a
    // ready error proves the state check ran first.
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => assert_state_error(result),
        Poll::Pending => panic!("state verification must complete before network I/O"),
    }
}
