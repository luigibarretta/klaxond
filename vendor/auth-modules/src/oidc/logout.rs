use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "oidc-async")]
use super::async_client::PreparedAsyncOidcClient;
use super::{types::OidcProviderMetadata, OidcClientConfig, OidcError, OidcSigningAlgorithm};

const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const MAX_LOGOUT_TOKEN_AGE_SECONDS: i64 = 300;
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Eq, PartialEq)]
pub struct OidcBackchannelLogout {
    pub issuer: String,
    pub subject: Option<String>,
    pub provider_session_id: Option<String>,
    pub token_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: Option<i64>,
}

impl fmt::Debug for OidcBackchannelLogout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcBackchannelLogout")
            .field("issuer", &self.issuer)
            .field("subject_present", &self.subject.is_some())
            .field(
                "provider_session_id_present",
                &self.provider_session_id.is_some(),
            )
            .field("token_id", &"[REDACTED]")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LogoutClaims {
    iss: String,
    aud: AudienceClaim,
    iat: i64,
    #[serde(default)]
    exp: Option<i64>,
    jti: String,
    events: BTreeMap<String, Value>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    nonce: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains_exactly(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.len() == 1 && values[0] == expected,
        }
    }
}

#[cfg(feature = "oidc-async")]
pub async fn validate_backchannel_logout_token(
    config: &OidcClientConfig,
    raw_token: &str,
) -> Result<OidcBackchannelLogout, OidcError> {
    PreparedAsyncOidcClient::discover(config)
        .await?
        .validate_backchannel_logout_token(config, raw_token)
}

pub(crate) fn validate_backchannel_logout_token_with_jwks(
    config: &OidcClientConfig,
    raw_token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
) -> Result<OidcBackchannelLogout, OidcError> {
    if raw_token.len() > 16 * 1024 {
        return Err(OidcError::new("OIDC logout token is too large"));
    }
    let header = jsonwebtoken::decode_header(raw_token)
        .map_err(|err| OidcError::new(format!("invalid OIDC logout token header: {err}")))?;
    let algorithm = config
        .allowed_signing_algorithms
        .iter()
        .copied()
        .find_map(|allowed| {
            let algorithm = jwt_algorithm(allowed);
            (algorithm == header.alg).then_some(algorithm)
        })
        .ok_or_else(|| OidcError::new("OIDC logout token uses a disallowed signing algorithm"))?;
    if header
        .typ
        .as_deref()
        .is_some_and(|value| value != "logout+jwt")
    {
        return Err(OidcError::new(
            "OIDC logout token has an unexpected token type",
        ));
    }

    let matching_keys = jwks
        .keys
        .iter()
        .filter(|key| logout_key_matches(key, &header, algorithm))
        .collect::<Vec<_>>();
    if matching_keys.len() != 1 {
        return Err(OidcError::new(
            "OIDC logout token signing key is missing or ambiguous",
        ));
    }
    let key = jsonwebtoken::DecodingKey::from_jwk(matching_keys[0])
        .map_err(|err| OidcError::new(format!("OIDC logout token key is invalid: {err}")))?;
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<LogoutClaims>(raw_token, &key, &validation)
        .map_err(|err| OidcError::new(format!("OIDC logout token signature failed: {err}")))?;
    validate_claims(config, claims.claims)
}

pub(crate) fn jwks_from_metadata(
    metadata: &OidcProviderMetadata,
) -> Result<jsonwebtoken::jwk::JwkSet, OidcError> {
    serde_json::from_value(
        serde_json::to_value(metadata.jwks())
            .map_err(|err| OidcError::new(format!("serialize OIDC provider keys failed: {err}")))?,
    )
    .map_err(|err| OidcError::new(format!("parse OIDC provider keys failed: {err}")))
}

fn logout_key_matches(
    key: &jsonwebtoken::jwk::Jwk,
    header: &jsonwebtoken::Header,
    algorithm: jsonwebtoken::Algorithm,
) -> bool {
    use jsonwebtoken::jwk::{KeyOperations, PublicKeyUse};

    let common = &key.common;
    let id_matches = header
        .kid
        .as_deref()
        .is_none_or(|expected| common.key_id.as_deref() == Some(expected));
    let intended_for_signatures = common
        .public_key_use
        .as_ref()
        .is_none_or(|value| value == &PublicKeyUse::Signature);
    let permits_only_verification = common.key_operations.as_ref().is_none_or(|operations| {
        !operations.is_empty()
            && operations
                .iter()
                .all(|operation| operation == &KeyOperations::Verify)
    });
    let algorithm_matches = common
        .key_algorithm
        .as_ref()
        .is_none_or(|expected| expected.to_string() == algorithm_name(algorithm));

    id_matches && intended_for_signatures && permits_only_verification && algorithm_matches
}

fn algorithm_name(algorithm: jsonwebtoken::Algorithm) -> &'static str {
    match algorithm {
        jsonwebtoken::Algorithm::HS256 => "HS256",
        jsonwebtoken::Algorithm::HS384 => "HS384",
        jsonwebtoken::Algorithm::HS512 => "HS512",
        jsonwebtoken::Algorithm::ES256 => "ES256",
        jsonwebtoken::Algorithm::ES384 => "ES384",
        jsonwebtoken::Algorithm::RS256 => "RS256",
        jsonwebtoken::Algorithm::RS384 => "RS384",
        jsonwebtoken::Algorithm::RS512 => "RS512",
        jsonwebtoken::Algorithm::PS256 => "PS256",
        jsonwebtoken::Algorithm::PS384 => "PS384",
        jsonwebtoken::Algorithm::PS512 => "PS512",
        jsonwebtoken::Algorithm::EdDSA => "EdDSA",
    }
}

fn jwt_algorithm(algorithm: OidcSigningAlgorithm) -> jsonwebtoken::Algorithm {
    match algorithm {
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256 => jsonwebtoken::Algorithm::RS256,
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha384 => jsonwebtoken::Algorithm::RS384,
        OidcSigningAlgorithm::RsaSsaPkcs1V15Sha512 => jsonwebtoken::Algorithm::RS512,
        OidcSigningAlgorithm::RsaSsaPssSha256 => jsonwebtoken::Algorithm::PS256,
        OidcSigningAlgorithm::RsaSsaPssSha384 => jsonwebtoken::Algorithm::PS384,
        OidcSigningAlgorithm::RsaSsaPssSha512 => jsonwebtoken::Algorithm::PS512,
        OidcSigningAlgorithm::EcdsaP256Sha256 => jsonwebtoken::Algorithm::ES256,
        OidcSigningAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
    }
}

fn validate_claims(
    config: &OidcClientConfig,
    claims: LogoutClaims,
) -> Result<OidcBackchannelLogout, OidcError> {
    if claims.iss != config.issuer_url {
        return Err(OidcError::new("OIDC logout token issuer mismatch"));
    }
    if !claims.aud.contains_exactly(&config.client_id) {
        return Err(OidcError::new("OIDC logout token audience mismatch"));
    }
    if claims.nonce.is_some() {
        return Err(OidcError::new("OIDC logout token must not contain nonce"));
    }
    if claims.events.len() != 1
        || claims
            .events
            .get(LOGOUT_EVENT)
            .is_none_or(|value| value.as_object().is_none_or(|object| !object.is_empty()))
    {
        return Err(OidcError::new("OIDC logout token event is invalid"));
    }
    let subject = non_empty_bounded(claims.sub, 255, "subject")?;
    let provider_session_id = non_empty_bounded(claims.sid, 255, "session id")?;
    if subject.is_none() && provider_session_id.is_none() {
        return Err(OidcError::new("OIDC logout token requires sid or subject"));
    }
    let token_id = non_empty_bounded(Some(claims.jti), 255, "token id")?
        .ok_or_else(|| OidcError::new("OIDC logout token requires jti"))?;
    let now = unix_time()?;
    if claims.iat > now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(claims.iat)
            > MAX_LOGOUT_TOKEN_AGE_SECONDS.saturating_add(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(OidcError::new(
            "OIDC logout token issue time is outside the accepted window",
        ));
    }
    if claims
        .exp
        .is_some_and(|expires_at| expires_at.saturating_add(MAX_CLOCK_SKEW_SECONDS) < now)
    {
        return Err(OidcError::new("OIDC logout token has expired"));
    }
    Ok(OidcBackchannelLogout {
        issuer: claims.iss,
        subject,
        provider_session_id,
        token_id,
        issued_at_unix: claims.iat,
        expires_at_unix: claims.exp,
    })
}

fn non_empty_bounded(
    value: Option<String>,
    maximum: usize,
    name: &str,
) -> Result<Option<String>, OidcError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(OidcError::new(format!(
            "OIDC logout token {name} is invalid"
        )));
    }
    Ok(Some(value))
}

fn unix_time() -> Result<i64, OidcError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OidcError::new("system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| OidcError::new("system clock exceeds supported range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EC_PRIVATE_KEY: &[u8] = &[
        48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
        61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 94, 42, 147, 188, 24, 146, 89, 44, 119, 181,
        209, 214, 149, 5, 143, 85, 207, 9, 148, 57, 206, 109, 166, 110, 205, 174, 83, 34, 151, 171,
        50, 234, 161, 68, 3, 66, 0, 4, 103, 64, 153, 164, 0, 201, 166, 194, 211, 226, 8, 43, 248,
        58, 114, 38, 183, 126, 250, 26, 79, 6, 119, 80, 80, 212, 108, 142, 240, 15, 253, 224, 162,
        52, 255, 113, 64, 247, 175, 148, 13, 241, 250, 188, 187, 74, 71, 58, 85, 213, 144, 73, 134,
        148, 249, 120, 53, 142, 208, 167, 184, 176, 170, 82,
    ];

    fn config() -> OidcClientConfig {
        OidcClientConfig::new(
            "https://identity.example.test/application/o/control/",
            "control-client",
            Some("secret".to_string()),
            "https://control.example.test/api/control/auth/callback",
            vec!["openid".to_string()],
        )
    }

    fn claims() -> LogoutClaims {
        let now = unix_time().expect("time");
        LogoutClaims {
            iss: config().issuer_url,
            aud: AudienceClaim::One("control-client".to_string()),
            iat: now,
            exp: Some(now + 60),
            jti: "logout-1".to_string(),
            events: BTreeMap::from([(LOGOUT_EVENT.to_string(), serde_json::json!({}))]),
            sid: Some("provider-session-1".to_string()),
            sub: None,
            nonce: None,
        }
    }

    #[test]
    fn logout_claims_require_exact_audience_and_event() {
        assert!(validate_claims(&config(), claims()).is_ok());
        let mut wrong_audience = claims();
        wrong_audience.aud =
            AudienceClaim::Many(vec!["control-client".into(), "other-client".into()]);
        assert!(validate_claims(&config(), wrong_audience).is_err());
        let mut wrong_event = claims();
        wrong_event
            .events
            .insert("other".to_string(), serde_json::json!({}));
        assert!(validate_claims(&config(), wrong_event).is_err());
    }

    #[test]
    fn logout_claims_reject_nonce_and_missing_correlation() {
        let mut nonce = claims();
        nonce.nonce = Some(Value::String("not-allowed".to_string()));
        assert!(validate_claims(&config(), nonce).is_err());
        let mut missing = claims();
        missing.sid = None;
        missing.sub = None;
        assert!(validate_claims(&config(), missing).is_err());
    }

    #[test]
    fn logout_claims_reject_stale_or_future_tokens() {
        let now = unix_time().expect("time");
        let mut stale = claims();
        stale.iat = now - MAX_LOGOUT_TOKEN_AGE_SECONDS - MAX_CLOCK_SKEW_SECONDS - 1;
        assert!(validate_claims(&config(), stale).is_err());
        let mut future = claims();
        future.iat = now + MAX_CLOCK_SKEW_SECONDS + 1;
        assert!(validate_claims(&config(), future).is_err());
    }

    #[test]
    fn logout_key_must_be_an_algorithm_matching_verification_key() {
        let key = |use_value: &str, operations: &[&str], algorithm: &str| {
            serde_json::from_value::<jsonwebtoken::jwk::Jwk>(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "y": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "kid": "signing-key",
                "use": use_value,
                "key_ops": operations,
                "alg": algorithm
            }))
            .expect("test JWK")
        };
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::ES256,
            kid: Some("signing-key".to_string()),
            ..jsonwebtoken::Header::default()
        };

        assert!(logout_key_matches(
            &key("sig", &["verify"], "ES256"),
            &header,
            jsonwebtoken::Algorithm::ES256
        ));
        assert!(!logout_key_matches(
            &key("enc", &["verify"], "ES256"),
            &header,
            jsonwebtoken::Algorithm::ES256
        ));
        assert!(!logout_key_matches(
            &key("sig", &["sign"], "ES256"),
            &header,
            jsonwebtoken::Algorithm::ES256
        ));
        assert!(!logout_key_matches(
            &key("sig", &["verify"], "RS256"),
            &header,
            jsonwebtoken::Algorithm::ES256
        ));
    }

    #[test]
    fn logout_identifiers_are_exact_and_canonical() {
        assert_eq!(
            non_empty_bounded(Some("subject-1".to_string()), 255, "subject")
                .expect("canonical identifier"),
            Some("subject-1".to_string())
        );
        assert!(non_empty_bounded(Some(" subject-1".to_string()), 255, "subject").is_err());
        assert!(non_empty_bounded(Some("subject-1 ".to_string()), 255, "subject").is_err());
    }

    #[test]
    fn signed_logout_tokens_reject_hostile_jwk_metadata_and_ambiguity() {
        let now = unix_time().expect("test clock");
        let claims = LogoutClaims {
            iss: "https://identity.example.test/application/o/control/".to_string(),
            aud: AudienceClaim::One("control-client".to_string()),
            iat: now,
            exp: Some(now + 300),
            jti: "logout-token-1".to_string(),
            events: BTreeMap::from([(LOGOUT_EVENT.to_string(), serde_json::json!({}))]),
            sub: Some("operator-1".to_string()),
            sid: Some("provider-session-1".to_string()),
            nonce: None,
        };
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::ES256,
            kid: Some("signing-key".to_string()),
            typ: Some("logout+jwt".to_string()),
            ..jsonwebtoken::Header::default()
        };
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_ec_der(TEST_EC_PRIVATE_KEY),
        )
        .expect("signed logout token");
        let jwk = |use_value: &str, operations: &[&str], algorithm: &str| {
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "Z0CZpADJpsLT4ggr-DpyJrd--hpPBndQUNRsjvAP_eA",
                "y": "ojT_cUD3r5QN8fq8u0pHOlXVkEmGlPl4NY7Qp7iwqlI",
                "kid": "signing-key",
                "use": use_value,
                "key_ops": operations,
                "alg": algorithm
            })
        };
        let set = |keys: Vec<serde_json::Value>| {
            serde_json::from_value::<jsonwebtoken::jwk::JwkSet>(serde_json::json!({ "keys": keys }))
                .expect("test JWK set")
        };
        let valid = jwk("sig", &["verify"], "ES256");

        assert!(validate_backchannel_logout_token_with_jwks(
            &config(),
            &token,
            &set(vec![valid.clone()])
        )
        .is_ok());
        assert!(validate_backchannel_logout_token_with_jwks(
            &config(),
            &token,
            &set(vec![jwk("enc", &["verify"], "ES256")])
        )
        .is_err());
        assert!(validate_backchannel_logout_token_with_jwks(
            &config(),
            &token,
            &set(vec![jwk("sig", &["sign"], "ES256")])
        )
        .is_err());
        assert!(validate_backchannel_logout_token_with_jwks(
            &config(),
            &token,
            &set(vec![jwk("sig", &["verify"], "RS256")])
        )
        .is_err());
        assert!(validate_backchannel_logout_token_with_jwks(
            &config(),
            &token,
            &set(vec![valid.clone(), valid])
        )
        .is_err());
    }
}
