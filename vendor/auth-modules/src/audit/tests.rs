use super::*;
use crate::methods;

#[test]
fn audit_kind_names_are_stable() {
    assert_eq!(
        AuthAuditKind::MagicLinkRequested.as_str(),
        "magic_link_requested"
    );
    assert_eq!(
        AuthAuditKind::BruteForceDetected.as_str(),
        "brute_force_detected"
    );
}

#[test]
fn login_failure_constructor_sets_expected_risk() {
    let event = AuthAuditEvent::login_failure("alice", methods::PASSWORD);

    assert_eq!(event.kind, AuthAuditKind::LoginFailure);
    assert_eq!(event.outcome, AuthOutcome::Failure);
    assert_eq!(event.risk_level, RiskLevel::Medium);
    assert_eq!(event.subject.as_deref(), Some("alice"));
    assert_eq!(event.method, Some(methods::PASSWORD));
}

#[test]
fn builder_keeps_request_context_and_details() {
    let event = AuthAuditEvent::builder(AuthAuditKind::OidcLoginRejected)
        .outcome(AuthOutcome::Denied)
        .risk_level(RiskLevel::High)
        .context(
            AuthRequestContext::new()
                .ip_address("203.0.113.7")
                .request_id("req-1"),
        )
        .detail("provider", "authentik")
        .build();

    assert_eq!(event.context.ip_address.as_deref(), Some("203.0.113.7"));
    assert_eq!(
        event.details,
        vec![("provider".to_string(), "authentik".to_string())]
    );
}
