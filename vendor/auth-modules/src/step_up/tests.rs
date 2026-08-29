use super::*;

#[test]
fn default_policy_does_not_require_step_up() {
    let policy = StepUpPolicy::default();

    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Oidc),
        StepUpRequirement::none()
    );
}

#[test]
fn passkey_policy_requires_passkey_after_primary_auth() {
    let policy = StepUpPolicy::passkey_required_after_primary();

    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Oidc),
        StepUpRequirement::passkey("primary_auth_step_up")
    );
    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Password),
        StepUpRequirement::passkey("primary_auth_step_up")
    );
    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Passkey),
        StepUpRequirement::none()
    );
}

#[test]
fn totp_policy_requires_totp_after_primary_auth() {
    let policy = StepUpPolicy::totp_required_after_primary();

    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Oidc),
        StepUpRequirement {
            required: true,
            factor: Some(StepUpFactor::Totp),
            reason: "primary_auth_step_up"
        }
    );
    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Passkey),
        StepUpRequirement {
            required: true,
            factor: Some(StepUpFactor::Totp),
            reason: "primary_auth_step_up"
        }
    );
}

#[test]
fn parses_primary_methods_and_factors() {
    assert_eq!(
        PrimaryAuthMethod::parse("basic"),
        Some(PrimaryAuthMethod::Password)
    );
    assert_eq!(
        PrimaryAuthMethod::parse("api-token"),
        Some(PrimaryAuthMethod::ApiToken)
    );
    assert_eq!(
        PrimaryAuthMethod::parse("magic_link"),
        Some(PrimaryAuthMethod::MagicLink)
    );
    assert_eq!(StepUpFactor::parse("otp"), Some(StepUpFactor::Totp));
    assert_eq!(
        StepUpFactor::parse("security-key"),
        Some(StepUpFactor::HardwareKey)
    );
}

#[test]
fn hardware_key_factor_is_satisfied_by_passkey_primary() {
    let policy = StepUpPolicy::required_after_primary(StepUpFactor::HardwareKey);

    assert_eq!(
        policy.requirement_after_primary(PrimaryAuthMethod::Passkey),
        StepUpRequirement::none()
    );
}

#[test]
fn required_step_up_fails_closed_without_browser_primary_authentication() {
    let policy = StepUpPolicy::totp_required_after_primary();

    for primary in [PrimaryAuthMethod::None, PrimaryAuthMethod::ApiToken] {
        assert_eq!(
            policy.requirement_after_primary(primary),
            StepUpRequirement::unsatisfiable("primary_auth_cannot_satisfy_step_up")
        );
    }
}
