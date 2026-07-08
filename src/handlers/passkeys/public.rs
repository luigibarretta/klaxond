use crate::config::{PasskeyRecord, RuntimeConfig};
use serde_json::{Value, json};
use url::Url;

pub(in crate::handlers) fn webauthn_public_config(cfg: &RuntimeConfig) -> Value {
    let origin = if cfg.auth.webauthn.origin.trim().is_empty() {
        cfg.public_url.trim_end_matches('/').to_string()
    } else {
        cfg.auth.webauthn.origin.trim_end_matches('/').to_string()
    };
    let rp_id = if cfg.auth.webauthn.rp_id.trim().is_empty() {
        Url::parse(&origin)
            .ok()
            .and_then(|url| url.domain().map(ToOwned::to_owned))
            .unwrap_or_default()
    } else {
        cfg.auth.webauthn.rp_id.clone()
    };
    json!({
        "enabled": cfg.auth.webauthn.enabled,
        "rp_id": rp_id,
        "origin": origin,
    })
}

pub(in crate::handlers) fn public_passkey(record: &PasskeyRecord) -> Value {
    json!({
        "id": record.id,
        "name": record.name,
        "user_sub": record.user_sub,
        "user_name": record.user_name,
        "user_email": record.user_email,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
    })
}
