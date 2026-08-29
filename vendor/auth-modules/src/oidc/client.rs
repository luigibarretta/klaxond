use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AuthenticationContextClass, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse, StandardTokenResponse,
};

use super::{
    types::OidcProviderMetadata, OidcAdditionalClaims, OidcAuthorizationFlow, OidcClientConfig,
    OidcError, OidcSigningAlgorithm,
};

pub(crate) type SharedIdTokenFields = IdTokenFields<
    OidcAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub(crate) type SharedTokenResponse = StandardTokenResponse<SharedIdTokenFields, CoreTokenType>;

pub(crate) type SharedClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
    HasUserInfoUrl = EndpointNotSet,
> = Client<
    OidcAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    SharedTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub(crate) type ReadyClient = SharedClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub(crate) fn client_from_metadata(
    config: &OidcClientConfig,
    metadata: OidcProviderMetadata,
) -> Result<ReadyClient, OidcError> {
    let secret = config.client_secret.as_ref().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| ClientSecret::new(trimmed.to_string()))
    });
    let client = SharedClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        secret,
    )
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_url.clone())
            .map_err(|err| OidcError::new(format!("invalid OIDC redirect URL: {err}")))?,
    );
    Ok(client)
}

pub(crate) fn same_provider_configuration(
    left: &OidcClientConfig,
    right: &OidcClientConfig,
) -> bool {
    left.issuer_url == right.issuer_url
        && left.client_id == right.client_id
        && left.client_secret == right.client_secret
        && left.redirect_url == right.redirect_url
        && left.scopes == right.scopes
        && left.fetch_userinfo == right.fetch_userinfo
        && left.allowed_signing_algorithms == right.allowed_signing_algorithms
        && left.connect_timeout == right.connect_timeout
        && left.request_timeout == right.request_timeout
        && left.allow_insecure_http == right.allow_insecure_http
        && left.require_userinfo == right.require_userinfo
        && left.assurance_policy.required_authentication_context
            == right.assurance_policy.required_authentication_context
        && same_required_methods(
            &left.assurance_policy.required_authentication_methods,
            &right.assurance_policy.required_authentication_methods,
        )
        && left.assurance_policy.clock_skew == right.assurance_policy.clock_skew
}

fn same_required_methods(left: &[String], right: &[String]) -> bool {
    let mut left = left.iter().map(String::as_str).collect::<Vec<_>>();
    let mut right = right.iter().map(String::as_str).collect::<Vec<_>>();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

pub(crate) fn build_authorization_flow(
    client: &ReadyClient,
    config: &OidcClientConfig,
    state: &str,
) -> OidcAuthorizationFlow {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let state_value = state.to_string();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(state_value.clone()),
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);
    request = apply_assurance_request(request, config);

    for scope in &config.scopes {
        let scope = scope.trim();
        if !scope.is_empty() && scope != "openid" {
            request = request.add_scope(Scope::new(scope.to_string()));
        }
    }

    let (url, csrf, nonce) = request.url();
    OidcAuthorizationFlow {
        authorization_url: url.to_string(),
        state: csrf.secret().to_string(),
        nonce: nonce.secret().to_string(),
        pkce_verifier: pkce_verifier.secret().to_string(),
    }
}

pub(crate) fn build_authorization_flow_with_values(
    client: &ReadyClient,
    config: &OidcClientConfig,
    state: &str,
    nonce: &str,
    pkce_verifier: &str,
) -> OidcAuthorizationFlow {
    let verifier = PkceCodeVerifier::new(pkce_verifier.to_string());
    let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    let state_value = state.to_string();
    let nonce_value = nonce.to_string();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(state_value.clone()),
            move || Nonce::new(nonce_value.clone()),
        )
        .set_pkce_challenge(pkce_challenge);
    request = apply_assurance_request(request, config);

    for scope in &config.scopes {
        let scope = scope.trim();
        if !scope.is_empty() && scope != "openid" {
            request = request.add_scope(Scope::new(scope.to_string()));
        }
    }

    let (url, csrf, nonce) = request.url();
    OidcAuthorizationFlow {
        authorization_url: url.to_string(),
        state: csrf.secret().to_string(),
        nonce: nonce.secret().to_string(),
        pkce_verifier: verifier.secret().to_string(),
    }
}

fn apply_assurance_request<'a>(
    mut request: openidconnect::AuthorizationRequest<
        'a,
        CoreAuthDisplay,
        CoreAuthPrompt,
        CoreResponseType,
    >,
    config: &OidcClientConfig,
) -> openidconnect::AuthorizationRequest<'a, CoreAuthDisplay, CoreAuthPrompt, CoreResponseType> {
    let policy = &config.assurance_policy;
    if let Some(context) = policy
        .required_authentication_context
        .as_deref()
        .filter(|context| !context.trim().is_empty())
    {
        request = request
            .add_auth_context_value(AuthenticationContextClass::new(context.trim().to_string()));
    }
    if let Some(maximum_age) = policy.maximum_authentication_age {
        request = request.set_max_age(maximum_age);
    }
    if policy.force_reauthentication {
        request = request.add_prompt(CoreAuthPrompt::Login);
    }
    request
}

pub(crate) fn signing_algorithm(algorithm: OidcSigningAlgorithm) -> CoreJwsSigningAlgorithm {
    match algorithm {
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256 => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha384 => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha512 => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
        OidcSigningAlgorithm::RsaSsaPssSha256 => CoreJwsSigningAlgorithm::RsaSsaPssSha256,
        OidcSigningAlgorithm::RsaSsaPssSha384 => CoreJwsSigningAlgorithm::RsaSsaPssSha384,
        OidcSigningAlgorithm::RsaSsaPssSha512 => CoreJwsSigningAlgorithm::RsaSsaPssSha512,
        OidcSigningAlgorithm::EcdsaP256Sha256 => CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        OidcSigningAlgorithm::EdDsa => CoreJwsSigningAlgorithm::EdDsa,
    }
}

#[cfg(test)]
mod tests;
