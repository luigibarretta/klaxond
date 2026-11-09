//! Discovery-document types, used only by the protocol clients.

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{AdditionalProviderMetadata, PkceCodeChallengeMethod, ProviderMetadata};
use serde::{Deserialize, Serialize};

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
