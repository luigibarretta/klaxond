use super::User;
use crate::config::AuthConfig;
use crate::state::{AppState, PendingStepUpState, lock_mutex};
use crate::util::token_urlsafe;
use auth_modules::step_up::{PrimaryAuthMethod, StepUpFactor, StepUpRequirement};

const STEP_UP_TTL_SECONDS: f64 = 600.0;

pub(crate) fn redirect_location_after_primary(
    state: &AppState,
    auth: &AuthConfig,
    user: User,
    return_to: &str,
    primary: PrimaryAuthMethod,
) -> Option<String> {
    let requirement = auth.step_up_policy().requirement_after_primary(primary);
    if !requirement.required {
        return None;
    }
    if requirement
        .factor
        .is_some_and(|factor| user.second_factor == factor.as_str())
    {
        return None;
    }
    begin_step_up(state, user, return_to, requirement)
}

pub(super) fn second_factor_satisfied(
    auth: &AuthConfig,
    user: &User,
    primary: PrimaryAuthMethod,
) -> bool {
    let requirement = auth.step_up_policy().requirement_after_primary(primary);
    !requirement.required
        || requirement
            .factor
            .is_some_and(|factor| user.second_factor == factor.as_str())
}

#[derive(Clone, Debug)]
pub(crate) struct StepUpChallenge {
    pub return_to: String,
    pub user: User,
    pub factor: String,
    pub reason: String,
}

fn begin_step_up(
    state: &AppState,
    user: User,
    return_to: &str,
    requirement: StepUpRequirement,
) -> Option<String> {
    let factor = requirement.factor?;
    let token = token_urlsafe(24);
    {
        let mut pending = lock_mutex(&state.step_up_states, "step-up states");
        prune_expired(&mut pending);
        pending.insert(
            token.clone(),
            PendingStepUpState {
                created_at: crate::util::now_epoch(),
                return_to: return_to.to_string(),
                user,
                factor: factor.as_str().to_string(),
                reason: requirement.reason.to_string(),
            },
        );
    }
    Some(format!(
        "/api/auth/step-up?token={}&return_to={}",
        urlencoding::encode(&token),
        urlencoding::encode(return_to)
    ))
}

pub(crate) fn pending_step_up_challenge(state: &AppState, token: &str) -> Option<StepUpChallenge> {
    let mut pending = lock_mutex(&state.step_up_states, "step-up states");
    prune_expired(&mut pending);
    pending.get(token).map(|state| StepUpChallenge {
        return_to: state.return_to.clone(),
        user: state.user.clone(),
        factor: state.factor.clone(),
        reason: state.reason.clone(),
    })
}

pub(crate) fn pending_step_up_user_sub(state: &AppState, token: &str) -> Option<String> {
    pending_step_up_challenge(state, token).map(|state| state.user.sub)
}

pub(crate) fn finish_webauthn_step_up(
    state: &AppState,
    token: &str,
    user_sub: &str,
) -> Result<(User, String), String> {
    finish_step_up(
        state,
        token,
        user_sub,
        &[StepUpFactor::Passkey, StepUpFactor::HardwareKey],
    )
}

pub(crate) fn finish_totp_step_up(
    state: &AppState,
    token: &str,
    user_sub: &str,
) -> Result<(User, String), String> {
    finish_step_up(state, token, user_sub, &[StepUpFactor::Totp])
}

fn finish_step_up(
    state: &AppState,
    token: &str,
    user_sub: &str,
    allowed_factors: &[StepUpFactor],
) -> Result<(User, String), String> {
    let mut pending = lock_mutex(&state.step_up_states, "step-up states");
    prune_expired(&mut pending);
    let Some(state) = pending.get(token) else {
        return Err("unknown or expired step-up request".into());
    };
    if !allowed_factors
        .iter()
        .any(|factor| state.factor == factor.as_str())
    {
        return Err(format!("unsupported step-up factor '{}'", state.factor));
    }
    if state.user.sub != user_sub {
        return Err("second factor does not match the primary authenticated user".into());
    }
    let Some(mut state) = pending.remove(token) else {
        return Err("unknown or expired step-up request".into());
    };
    state.user.second_factor = state.factor.clone();
    state.user.sudo_until = super::sudo_until_deadline();
    Ok((state.user, state.return_to))
}

fn prune_expired(states: &mut std::collections::HashMap<String, PendingStepUpState>) {
    let cutoff = crate::util::now_epoch() - STEP_UP_TTL_SECONDS;
    states.retain(|_, pending| pending.created_at >= cutoff);
}
