use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const PKCE_CHALLENGE_METHOD: &str = "S256";
pub const PKCE_MIN_VERIFIER_LEN: usize = 43;
pub const PKCE_MAX_VERIFIER_LEN: usize = 128;
const PKCE_MIN_RANDOM_BYTES: usize = 32;
const PKCE_MAX_RANDOM_BYTES: usize = 96;
const DEFAULT_REJECT_PREFIXES: &[&str] = &["/auth", "/auth/", "/api/auth", "/api/auth/"];
const RESERVED_AUTHORIZATION_PARAMS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OidcPkceError {
    InvalidAuthorizationEndpoint,
    ReservedQueryParameter(String),
}

impl fmt::Display for OidcPkceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthorizationEndpoint => {
                formatter.write_str("invalid OIDC authorization endpoint")
            }
            Self::ReservedQueryParameter(parameter) => {
                write!(
                    formatter,
                    "OIDC authorization endpoint already contains reserved parameter {parameter}"
                )
            }
        }
    }
}

impl std::error::Error for OidcPkceError {}

#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl fmt::Debug for PkcePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkcePair")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizeUrlParams<'a> {
    pub authorization_endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: Option<&'a str>,
    pub code_challenge: &'a str,
}

impl fmt::Debug for AuthorizeUrlParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizeUrlParams")
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &"[REDACTED]")
            .field("nonce", &self.nonce.map(|_| "[REDACTED]"))
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRedirectPolicy<'a> {
    pub fallback: &'a str,
    pub max_len: usize,
    pub reject_prefixes: &'a [&'a str],
}

impl Default for LocalRedirectPolicy<'_> {
    fn default() -> Self {
        Self {
            fallback: "/",
            max_len: 2048,
            reject_prefixes: DEFAULT_REJECT_PREFIXES,
        }
    }
}

pub fn random_url_token(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn pkce_pair(bytes_len: usize) -> PkcePair {
    let verifier = random_url_token(bytes_len.clamp(PKCE_MIN_RANDOM_BYTES, PKCE_MAX_RANDOM_BYTES));
    let challenge = pkce_challenge(&verifier);
    PkcePair {
        verifier,
        challenge,
    }
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn valid_pkce_verifier(verifier: &str) -> bool {
    (PKCE_MIN_VERIFIER_LEN..=PKCE_MAX_VERIFIER_LEN).contains(&verifier.len())
        && verifier.bytes().all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
        )
}

pub fn build_authorize_url(params: AuthorizeUrlParams<'_>) -> Result<String, OidcPkceError> {
    let mut endpoint = url::Url::parse(params.authorization_endpoint)
        .map_err(|_| OidcPkceError::InvalidAuthorizationEndpoint)?;
    if endpoint.fragment().is_some() || !matches!(endpoint.scheme(), "https" | "http") {
        return Err(OidcPkceError::InvalidAuthorizationEndpoint);
    }
    if let Some(parameter) = endpoint
        .query_pairs()
        .map(|(key, _)| key.into_owned())
        .find(|key| RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str()))
    {
        return Err(OidcPkceError::ReservedQueryParameter(parameter));
    }

    let mut query = vec![
        ("response_type", "code"),
        ("client_id", params.client_id),
        ("redirect_uri", params.redirect_uri),
        ("scope", params.scope),
        ("state", params.state),
    ];
    if let Some(nonce) = params.nonce {
        query.push(("nonce", nonce));
    }
    query.push(("code_challenge", params.code_challenge));
    query.push(("code_challenge_method", PKCE_CHALLENGE_METHOD));

    endpoint.query_pairs_mut().extend_pairs(query);
    Ok(endpoint.into())
}

pub fn sanitize_local_redirect(value: Option<&str>, policy: LocalRedirectPolicy<'_>) -> String {
    let fallback = if policy.fallback.starts_with('/') && !policy.fallback.starts_with("//") {
        policy.fallback
    } else {
        "/"
    };
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return fallback.to_string();
    };
    let path = value.split(['?', '#']).next().unwrap_or(value);
    if value.len() > policy.max_len
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.starts_with("/\\")
        || value.chars().any(char::is_control)
        || policy
            .reject_prefixes
            .iter()
            .any(|prefix| path == *prefix || (prefix.ends_with('/') && path.starts_with(prefix)))
    {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests;
