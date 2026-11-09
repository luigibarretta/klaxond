use std::time::Duration;

use super::client::same_provider_configuration;
use super::{OidcAssurancePolicy, OidcClientConfig};

fn config() -> OidcClientConfig {
    OidcClientConfig::new(
        "https://identity.example.test/application/o/control/",
        "control-client",
        Some("secret".to_string()),
        "https://control.example.test/api/control/auth/callback",
        vec!["openid".to_string(), "studioflow_control".to_string()],
    )
    .with_assurance_policy(
        OidcAssurancePolicy::requiring_context("control-mfa")
            .with_required_authentication_methods(["mfa"]),
    )
    .with_http_timeouts(Duration::from_secs(2), Duration::from_secs(10))
}

#[test]
fn prepared_provider_allows_only_assurance_policy_changes() {
    let baseline = config();
    let step_up = config().with_assurance_policy(
        OidcAssurancePolicy::requiring_context("control-mfa")
            .with_required_authentication_methods(["mfa"])
            .with_maximum_authentication_age(Duration::ZERO)
            .forcing_reauthentication(),
    );
    assert!(same_provider_configuration(&baseline, &step_up));

    let mut different_issuer = step_up.clone();
    different_issuer.issuer_url = "https://other.example.test/".to_string();
    assert!(!same_provider_configuration(&baseline, &different_issuer));

    let mut different_secret = step_up;
    different_secret.client_secret = Some("other-secret".to_string());
    assert!(!same_provider_configuration(&baseline, &different_secret));

    let mut weaker_context = baseline.clone();
    weaker_context
        .assurance_policy
        .required_authentication_context = None;
    assert!(!same_provider_configuration(&baseline, &weaker_context));

    let mut weaker_methods = baseline.clone();
    weaker_methods
        .assurance_policy
        .required_authentication_methods
        .clear();
    assert!(!same_provider_configuration(&baseline, &weaker_methods));

    let mut larger_clock_skew = baseline.clone();
    larger_clock_skew.assurance_policy.clock_skew = Duration::from_secs(120);
    assert!(!same_provider_configuration(&baseline, &larger_clock_skew));
}
