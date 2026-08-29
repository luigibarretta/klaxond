mod assurance;
#[cfg(any(feature = "oidc-async", feature = "oidc-blocking"))]
mod client;
#[cfg(any(feature = "oidc-async", feature = "oidc-blocking"))]
mod identity;
#[cfg(any(feature = "oidc-async", feature = "oidc-blocking"))]
mod logout;
#[cfg(any(feature = "oidc-async", feature = "oidc-blocking"))]
mod security;
mod types;

#[cfg(feature = "oidc-async")]
pub mod async_client;
#[cfg(feature = "oidc-blocking")]
pub mod blocking;

pub use assurance::{OidcAssurance, OidcAssurancePolicy, OidcSigningAlgorithm};
#[cfg(feature = "oidc-async")]
pub use async_client::PreparedAsyncOidcClient;
#[cfg(feature = "oidc-async")]
pub use logout::validate_backchannel_logout_token;
#[cfg(any(feature = "oidc-async", feature = "oidc-blocking"))]
pub use logout::OidcBackchannelLogout;
pub use types::{
    OidcAdditionalClaims, OidcAuthorizationFlow, OidcClientConfig, OidcError, OidcIdentity,
};

#[cfg(test)]
mod tests;
