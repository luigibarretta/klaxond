use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, PkceCodeChallengeMethod, ProviderMetadata,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::assurance::DEFAULT_ASYMMETRIC_SIGNING_ALGORITHMS;
use super::{OidcAssurance, OidcAssurancePolicy, OidcSigningAlgorithm};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct OidcProviderAdditionalMetadata {
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
}

impl AdditionalProviderMetadata for OidcProviderAdditionalMetadata {}

pub(crate) type OidcProviderMetadata = ProviderMetadata<
    OidcProviderAdditionalMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[derive(Clone, Eq, PartialEq)]
pub struct OidcClientConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub fetch_userinfo: bool,
    pub assurance_policy: OidcAssurancePolicy,
    pub allowed_signing_algorithms: Vec<OidcSigningAlgorithm>,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub allow_insecure_http: bool,
    pub require_userinfo: bool,
}

impl fmt::Debug for OidcClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcClientConfig")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("fetch_userinfo", &self.fetch_userinfo)
            .field("assurance_policy", &self.assurance_policy)
            .field(
                "allowed_signing_algorithms",
                &self.allowed_signing_algorithms,
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("require_userinfo", &self.require_userinfo)
            .finish()
    }
}

impl OidcClientConfig {
    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_url: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_url: redirect_url.into(),
            scopes,
            fetch_userinfo: false,
            assurance_policy: OidcAssurancePolicy::default(),
            allowed_signing_algorithms: DEFAULT_ASYMMETRIC_SIGNING_ALGORITHMS.to_vec(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            allow_insecure_http: false,
            require_userinfo: false,
        }
    }

    pub fn with_userinfo(mut self, fetch_userinfo: bool) -> Self {
        self.fetch_userinfo = fetch_userinfo;
        self
    }

    pub fn with_assurance_policy(mut self, assurance_policy: OidcAssurancePolicy) -> Self {
        self.assurance_policy = assurance_policy;
        self
    }

    pub fn with_allowed_signing_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = OidcSigningAlgorithm>,
    ) -> Self {
        self.allowed_signing_algorithms = algorithms.into_iter().collect();
        self
    }

    pub fn with_http_timeouts(
        mut self,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.request_timeout = request_timeout;
        self
    }

    pub fn allowing_insecure_http_for_development(mut self) -> Self {
        self.allow_insecure_http = true;
        self
    }

    pub fn with_required_userinfo(mut self, required: bool) -> Self {
        self.fetch_userinfo = required || self.fetch_userinfo;
        self.require_userinfo = required;
        self
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OidcAuthorizationFlow {
    pub authorization_url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

impl fmt::Debug for OidcAuthorizationFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthorizationFlow")
            .field("authorization_url", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct OidcIdentity {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: String,
    pub groups: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub assurance: OidcAssurance,
}

impl fmt::Debug for OidcIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcIdentity")
            .field("subject", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("email_present", &self.email.is_some())
            .field("email_verified", &self.email_verified)
            .field("name", &"[REDACTED]")
            .field("group_count", &self.groups.len())
            .field("claim_count", &self.claims.len())
            .field("assurance", &self.assurance)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct OidcAdditionalClaims {
    #[serde(default, deserialize_with = "deserialize_groups")]
    pub groups: Vec<String>,
    #[serde(flatten)]
    pub raw: BTreeMap<String, Value>,
}

impl AdditionalClaims for OidcAdditionalClaims {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OidcError {
    message: String,
}

impl OidcError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OidcError {}

fn deserialize_groups<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        Some(Value::Array(values)) => values
            .into_iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    serde::de::Error::custom("OIDC groups must contain only strings")
                })
            })
            .collect(),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(vec![value]),
        Some(Value::String(_)) | Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(serde::de::Error::custom(
            "OIDC groups must be a string or an array of strings",
        )),
    }
}
