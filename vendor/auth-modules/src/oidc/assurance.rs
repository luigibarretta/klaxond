use std::fmt;
use std::time::Duration;

/// Verified authentication context carried by an OIDC ID token.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OidcAssurance {
    pub issuer: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub authenticated_at_unix: Option<i64>,
    pub authentication_context: Option<String>,
    pub authentication_methods: Vec<String>,
    pub provider_session_id: Option<String>,
}

impl fmt::Debug for OidcAssurance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAssurance")
            .field("issuer", &self.issuer)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("authenticated_at_unix", &self.authenticated_at_unix)
            .field("authentication_context", &self.authentication_context)
            .field("authentication_methods", &self.authentication_methods)
            .field(
                "provider_session_id",
                &self.provider_session_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Assurance requirements applied to both the authorization request and ID-token validation.
///
/// Authentication method references are provider-defined. Consumers should only require values
/// that their configured identity provider emits under a reviewed claim mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcAssurancePolicy {
    pub required_authentication_context: Option<String>,
    pub required_authentication_methods: Vec<String>,
    pub maximum_authentication_age: Option<Duration>,
    pub clock_skew: Duration,
    pub force_reauthentication: bool,
}

impl Default for OidcAssurancePolicy {
    fn default() -> Self {
        Self {
            required_authentication_context: None,
            required_authentication_methods: Vec::new(),
            maximum_authentication_age: None,
            clock_skew: Duration::from_secs(60),
            force_reauthentication: false,
        }
    }
}

impl OidcAssurancePolicy {
    pub fn requiring_context(context: impl Into<String>) -> Self {
        Self {
            required_authentication_context: Some(context.into()),
            ..Self::default()
        }
    }

    pub fn with_required_authentication_methods(
        mut self,
        methods: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required_authentication_methods = methods.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_maximum_authentication_age(mut self, age: Duration) -> Self {
        self.maximum_authentication_age = Some(age);
        self
    }

    pub fn with_clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    pub fn forcing_reauthentication(mut self) -> Self {
        self.force_reauthentication = true;
        self
    }
}

/// Asymmetric ID-token signing algorithms that a consumer may explicitly allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcSigningAlgorithm {
    RsaSsaPkcs1V15Sha256,
    RsaSsaPkcs1V15Sha384,
    RsaSsaPkcs1V15Sha512,
    RsaSsaPssSha256,
    RsaSsaPssSha384,
    RsaSsaPssSha512,
    EcdsaP256Sha256,
    EdDsa,
}

pub(crate) const DEFAULT_ASYMMETRIC_SIGNING_ALGORITHMS: [OidcSigningAlgorithm; 8] = [
    OidcSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    OidcSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    OidcSigningAlgorithm::RsaSsaPkcs1V15Sha512,
    OidcSigningAlgorithm::RsaSsaPssSha256,
    OidcSigningAlgorithm::RsaSsaPssSha384,
    OidcSigningAlgorithm::RsaSsaPssSha512,
    OidcSigningAlgorithm::EcdsaP256Sha256,
    OidcSigningAlgorithm::EdDsa,
];
