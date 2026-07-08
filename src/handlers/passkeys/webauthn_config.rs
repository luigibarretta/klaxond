use crate::config::RuntimeConfig;
use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

pub(super) fn webauthn_for_cfg(cfg: &RuntimeConfig) -> Result<Webauthn, String> {
    if !cfg.auth.webauthn.enabled {
        return Err("WebAuthn/passkeys are disabled".into());
    }
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let url = Url::parse(&origin).map_err(|err| format!("invalid WebAuthn origin: {err}"))?;
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        url.domain()
            .ok_or_else(|| "WebAuthn origin must have a domain host".to_string())?
            .to_string()
    } else {
        cfg.auth.webauthn.rp_id.trim().to_string()
    };
    WebauthnBuilder::new(&rp_id, &url)
        .map_err(|err| format!("invalid WebAuthn relying party: {err}"))?
        .rp_name("klaxond")
        .allow_any_port(matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        ))
        .build()
        .map_err(|err| format!("invalid WebAuthn config: {err}"))
}
