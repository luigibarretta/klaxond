use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
};
use openidconnect::{AccessTokenHash, IdTokenClaims, OAuth2TokenResponse};
use std::time::{SystemTime, UNIX_EPOCH};

use super::client::{signing_algorithm, SharedTokenResponse};
use super::{OidcAdditionalClaims, OidcAssurance, OidcClientConfig, OidcError, OidcIdentity};

pub(crate) fn validate_access_token_hash(
    claims: &IdTokenClaims<OidcAdditionalClaims, CoreGenderClaim>,
    id_token: &openidconnect::IdToken<
        OidcAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    token: &SharedTokenResponse,
    verifier: &openidconnect::IdTokenVerifier<'_, CoreJsonWebKey>,
) -> Result<(), OidcError> {
    if let Some(expected_hash) = claims.access_token_hash() {
        let actual_hash = AccessTokenHash::from_token(
            token.access_token(),
            id_token.signing_alg().map_err(|err| {
                OidcError::new(format!("OIDC signing algorithm unavailable: {err}"))
            })?,
            id_token
                .signing_key(verifier)
                .map_err(|err| OidcError::new(format!("OIDC signing key unavailable: {err}")))?,
        )
        .map_err(|err| OidcError::new(format!("OIDC access token hash failed: {err}")))?;
        if actual_hash != *expected_hash {
            return Err(OidcError::new("OIDC access token hash mismatch"));
        }
    }
    Ok(())
}

pub(crate) fn validate_authorized_party(
    claims: &IdTokenClaims<OidcAdditionalClaims, CoreGenderClaim>,
    config: &OidcClientConfig,
) -> Result<(), OidcError> {
    if claims.audiences().len() > 1 && claims.authorized_party().is_none() {
        return Err(OidcError::new(
            "OIDC authorized party is required for a token with multiple audiences",
        ));
    }
    if claims
        .authorized_party()
        .is_some_and(|party| party.as_str() != config.client_id)
    {
        return Err(OidcError::new(
            "OIDC authorized party does not match the configured client",
        ));
    }
    Ok(())
}

pub(crate) fn identity_from_id_claims(
    claims: &openidconnect::IdTokenClaims<OidcAdditionalClaims, CoreGenderClaim>,
) -> OidcIdentity {
    let subject = claims.subject().as_str().to_string();
    let email = claims.email().map(|email| email.as_str().to_string());
    let username = claims
        .preferred_username()
        .map(|username| username.as_str().to_string())
        .or_else(|| email.clone())
        .unwrap_or_else(|| subject.clone());
    let name = claims
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.to_string())
        .unwrap_or_else(|| username.clone());
    let raw_claims = &claims.additional_claims().raw;
    OidcIdentity {
        subject,
        username,
        email,
        email_verified: claims.email_verified(),
        name,
        groups: claims.additional_claims().groups.clone(),
        claims: raw_claims.clone(),
        assurance: OidcAssurance {
            issuer: claims.issuer().url().to_string(),
            issued_at_unix: claims.issue_time().timestamp(),
            expires_at_unix: claims.expiration().timestamp(),
            authenticated_at_unix: claims.auth_time().map(|value| value.timestamp()),
            authentication_context: claims
                .auth_context_ref()
                .map(|context| context.as_ref().to_string()),
            authentication_methods: claims
                .auth_method_refs()
                .map(|methods| {
                    methods
                        .iter()
                        .map(|method| method.as_str().to_string())
                        .collect()
                })
                .unwrap_or_default(),
            provider_session_id: raw_claims
                .get("sid")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        },
    }
}

pub(crate) fn verifier_for_config<'a>(
    client: &'a super::client::ReadyClient,
    config: &OidcClientConfig,
) -> openidconnect::IdTokenVerifier<'a, CoreJsonWebKey> {
    let mut verifier = client.id_token_verifier();
    verifier = verifier.set_allowed_algs(
        config
            .allowed_signing_algorithms
            .iter()
            .copied()
            .map(signing_algorithm),
    );

    if let Some(required_context) = config
        .assurance_policy
        .required_authentication_context
        .clone()
    {
        verifier = verifier.set_auth_context_verifier_fn(move |actual| {
            let actual = actual.map(|context| context.as_ref());
            (actual == Some(required_context.as_str()))
                .then_some(())
                .ok_or_else(|| "required OIDC authentication context was not satisfied".to_string())
        });
    }

    if let Some(maximum_age) = config.assurance_policy.maximum_authentication_age {
        let clock_skew = config.assurance_policy.clock_skew;
        verifier = verifier.set_auth_time_verifier_fn(move |authenticated_at| {
            let authenticated_at = authenticated_at
                .ok_or_else(|| "OIDC auth_time is required by the assurance policy".to_string())?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch".to_string())?
                .as_secs();
            let now = i64::try_from(now)
                .map_err(|_| "system clock exceeds the supported OIDC range".to_string())?;
            let authenticated_at = authenticated_at.timestamp();
            let skew = i64::try_from(clock_skew.as_secs()).unwrap_or(i64::MAX);
            let maximum_age = i64::try_from(maximum_age.as_secs()).unwrap_or(i64::MAX);
            if authenticated_at > now.saturating_add(skew) {
                return Err("OIDC auth_time is in the future".to_string());
            }
            if now.saturating_sub(authenticated_at) > maximum_age.saturating_add(skew) {
                return Err("OIDC authentication is older than the allowed maximum".to_string());
            }
            Ok(())
        });
    }
    verifier
}

pub(crate) fn validate_required_authentication_methods(
    claims: &IdTokenClaims<OidcAdditionalClaims, CoreGenderClaim>,
    config: &OidcClientConfig,
) -> Result<(), OidcError> {
    let actual = claims.auth_method_refs().map_or(&[][..], Vec::as_slice);
    for required in &config.assurance_policy.required_authentication_methods {
        if !actual.iter().any(|method| method.as_str() == required) {
            return Err(OidcError::new(format!(
                "required OIDC authentication method was not satisfied: {required}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn merge_userinfo(
    identity: &mut OidcIdentity,
    userinfo: &openidconnect::UserInfoClaims<OidcAdditionalClaims, CoreGenderClaim>,
    authoritative: bool,
) {
    if let Some(email) = userinfo.email().map(|email| email.as_str().to_string()) {
        identity.email = Some(email);
    }
    if let Some(email_verified) = userinfo.email_verified() {
        identity.email_verified = Some(email_verified);
    }
    if let Some(username) = userinfo
        .preferred_username()
        .map(|username| username.as_str().to_string())
    {
        identity.username = username;
    }
    if let Some(name) = userinfo
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.to_string())
    {
        identity.name = name;
    }
    if authoritative || !userinfo.additional_claims().groups.is_empty() {
        identity.groups = userinfo.additional_claims().groups.clone();
    }
    for (key, value) in &userinfo.additional_claims().raw {
        identity.claims.insert(key.clone(), value.clone());
    }
}
