use std::marker::PhantomData;

use super::*;

/// Compile-time trait probes: the inherent constant wins only when the bound
/// holds, otherwise the blanket trait constant (`false`) is used.
struct Probe<T>(PhantomData<T>);

trait Fallback {
    const CLONE: bool = false;
    const DISPLAY: bool = false;
    const SERIALIZE: bool = false;
}

impl<T> Fallback for Probe<T> {}

#[allow(dead_code)]
impl<T: Clone> Probe<T> {
    const CLONE: bool = true;
}

#[allow(dead_code)]
impl<T: std::fmt::Display> Probe<T> {
    const DISPLAY: bool = true;
}

#[cfg(feature = "oidc")]
#[allow(dead_code)]
impl<T: serde::Serialize> Probe<T> {
    const SERIALIZE: bool = true;
}

fn issue() -> (StoredTokenHash, DeliverableToken) {
    issue_for_delivery(
        "alice@example.test",
        OneTimeTokenPurpose::MagicLink,
        OneTimeTokenPolicy::magic_link(),
        1_000,
    )
}

// Evaluated at compile time: implementing one of these traits for
// `DeliverableToken` breaks the test build.
#[test]
fn deliverable_token_cannot_be_cloned_displayed_or_serialized() {
    const { assert!(!Probe::<DeliverableToken>::CLONE) };
    const { assert!(!Probe::<DeliverableToken>::DISPLAY) };
    const { assert!(!Probe::<DeliverableToken>::SERIALIZE) };
    // Sanity check that the probes detect implemented traits.
    const { assert!(Probe::<String>::CLONE) };
    const { assert!(Probe::<String>::DISPLAY) };
    #[cfg(feature = "oidc")]
    const {
        assert!(Probe::<String>::SERIALIZE)
    };
}

#[test]
fn deliverable_token_debug_is_redacted() {
    let (record, token) = issue();
    let mut delivered = String::new();
    let debug = format!("{token:?}");
    token
        .deliver(|plaintext: &str| {
            delivered.push_str(plaintext);
            Ok::<(), std::convert::Infallible>(())
        })
        .expect("delivery");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&delivered));
    assert!(!format!("{record:?}").contains(&delivered));
}

#[test]
fn stored_hash_verifies_the_delivered_token_once() {
    let (mut record, token) = issue();
    assert_eq!(record.purpose, "magic_link");
    assert_eq!(record.expires_at_epoch, 1_600);
    assert_eq!(token.expires_at_epoch(), 1_600);

    let mut outbox = Vec::new();
    token
        .deliver(|plaintext: &str| {
            outbox.push(format!("https://app.example.test/login?token={plaintext}"));
            Ok::<(), std::convert::Infallible>(())
        })
        .expect("delivery");
    let link = outbox.pop().expect("one delivered link");
    let plaintext = link.rsplit('=').next().expect("token");

    assert_ne!(plaintext, record.token_hash);
    assert_eq!(
        verify_and_consume(
            &mut record,
            plaintext,
            &OneTimeTokenPurpose::MagicLink,
            1_100
        ),
        OneTimeTokenVerification::Accepted
    );
    assert_eq!(
        verify_and_consume(
            &mut record,
            plaintext,
            &OneTimeTokenPurpose::MagicLink,
            1_101
        ),
        OneTimeTokenVerification::Rejected(OneTimeTokenRejection::AlreadyConsumed)
    );
}

struct FailingMailer;

impl TokenDelivery for FailingMailer {
    type Error = &'static str;

    fn deliver(self, _token: &str) -> Result<(), Self::Error> {
        Err("smtp unavailable")
    }
}

#[test]
fn delivery_errors_are_returned_without_the_token() {
    let (_record, token) = issue();
    assert_eq!(token.deliver(FailingMailer), Err("smtp unavailable"));
}

#[test]
fn delivery_success_only_yields_unit() {
    let (_record, token) = issue();
    // The handler-facing result type carries no token material.
    let outcome: Result<(), std::convert::Infallible> = token.deliver(|_: &str| Ok(()));
    assert_eq!(outcome, Ok(()));
}
