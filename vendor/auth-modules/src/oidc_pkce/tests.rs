use super::*;

#[test]
fn pkce_challenge_is_s256_base64url_no_pad() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    assert_eq!(
        pkce_challenge(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn random_pkce_pair_uses_requested_entropy() {
    let pair = pkce_pair(32);

    assert_eq!(pair.challenge, pkce_challenge(&pair.verifier));
    assert_eq!(pair.verifier.len(), 43);
}

#[test]
fn random_pkce_pair_clamps_invalid_entropy_requests() {
    let too_short = pkce_pair(0);
    let too_long = pkce_pair(usize::MAX);

    assert!(valid_pkce_verifier(&too_short.verifier));
    assert!(valid_pkce_verifier(&too_long.verifier));
    assert_eq!(too_short.verifier.len(), PKCE_MIN_VERIFIER_LEN);
    assert_eq!(too_long.verifier.len(), PKCE_MAX_VERIFIER_LEN);
}

#[test]
fn debug_output_redacts_pkce_and_oidc_secrets() {
    let pair = PkcePair {
        verifier: "pkce-secret".to_string(),
        challenge: "public-challenge".to_string(),
    };
    let pair_debug = format!("{pair:?}");
    assert!(!pair_debug.contains("pkce-secret"));
    assert!(pair_debug.contains("public-challenge"));

    let params = AuthorizeUrlParams {
        authorization_endpoint: "https://idp.example/authorize",
        client_id: "client",
        redirect_uri: "https://app.example/api/auth/callback",
        scope: "openid",
        state: "state-secret",
        nonce: Some("nonce-secret"),
        code_challenge: "public-challenge",
    };
    let params_debug = format!("{params:?}");
    assert!(!params_debug.contains("state-secret"));
    assert!(!params_debug.contains("nonce-secret"));
}

#[test]
fn authorize_url_encodes_oidc_pkce_params() {
    let url = build_authorize_url(AuthorizeUrlParams {
        authorization_endpoint: "https://idp.example/authorize",
        client_id: "client 1",
        redirect_uri: "https://app.example/auth/callback",
        scope: "openid profile email",
        state: "STATE",
        nonce: Some("NONCE"),
        code_challenge: "CHALLENGE",
    })
    .expect("authorization URL");

    let parsed = url::Url::parse(&url).expect("parse authorization URL");
    let query = parsed
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        parsed.as_str().split('?').next(),
        Some("https://idp.example/authorize")
    );
    assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(query.get("client_id").map(String::as_str), Some("client 1"));
    assert_eq!(
        query.get("redirect_uri").map(String::as_str),
        Some("https://app.example/auth/callback")
    );
    assert_eq!(
        query.get("scope").map(String::as_str),
        Some("openid profile email")
    );
    assert_eq!(query.get("state").map(String::as_str), Some("STATE"));
    assert_eq!(query.get("nonce").map(String::as_str), Some("NONCE"));
    assert_eq!(
        query.get("code_challenge").map(String::as_str),
        Some("CHALLENGE")
    );
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
}

#[test]
fn authorize_url_appends_to_existing_query() {
    let url = build_authorize_url(AuthorizeUrlParams {
        authorization_endpoint: "https://idp.example/authorize?foo=bar",
        client_id: "client",
        redirect_uri: "redirect",
        scope: "openid",
        state: "state",
        nonce: None,
        code_challenge: "challenge",
    })
    .expect("authorization URL");

    assert!(url.contains("authorize?foo=bar&response_type=code"));
    assert!(!url.contains("nonce="));
}

#[test]
fn authorize_url_rejects_fragments_and_duplicate_protocol_parameters() {
    let params = |authorization_endpoint| AuthorizeUrlParams {
        authorization_endpoint,
        client_id: "client",
        redirect_uri: "redirect",
        scope: "openid",
        state: "state",
        nonce: None,
        code_challenge: "challenge",
    };

    assert_eq!(
        build_authorize_url(params("https://idp.example/authorize#fragment")),
        Err(OidcPkceError::InvalidAuthorizationEndpoint)
    );
    assert_eq!(
        build_authorize_url(params("https://idp.example/authorize?state=duplicate")),
        Err(OidcPkceError::ReservedQueryParameter("state".to_string()))
    );
}

#[test]
fn local_redirect_policy_rejects_external_control_and_auth_prefixes() {
    let policy = LocalRedirectPolicy::default();

    assert_eq!(
        sanitize_local_redirect(Some("/solid/?invite=abc"), policy.clone()),
        "/solid/?invite=abc"
    );
    assert_eq!(
        sanitize_local_redirect(Some("/authentication"), policy.clone()),
        "/authentication"
    );
    assert_eq!(
        sanitize_local_redirect(Some("https://evil.test"), policy.clone()),
        "/"
    );
    assert_eq!(
        sanitize_local_redirect(Some("//evil.test"), policy.clone()),
        "/"
    );
    assert_eq!(
        sanitize_local_redirect(Some("/bad\npath"), policy.clone()),
        "/"
    );
    assert_eq!(sanitize_local_redirect(Some("/auth"), policy.clone()), "/");
    assert_eq!(
        sanitize_local_redirect(Some("/auth?return=/dashboard"), policy.clone()),
        "/"
    );
    assert_eq!(
        sanitize_local_redirect(Some("/auth/login"), policy.clone()),
        "/"
    );
    assert_eq!(
        sanitize_local_redirect(Some("/api/auth/callback"), policy),
        "/"
    );
}
