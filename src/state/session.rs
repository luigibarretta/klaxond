use super::keys::ServiceKeys;
use crate::config::{Paths, RuntimeConfig};
use crate::util::private_file::{read_private, write_private};
use crate::util::random_bytes;
use anyhow::Result;

/// Loads the session secret (environment, then TOML, then the generated
/// `auth-session.key`) and derives the per-purpose key ring from it.
pub(in crate::state) fn load_service_keys(
    paths: &Paths,
    cfg: &RuntimeConfig,
) -> Result<ServiceKeys> {
    ServiceKeys::from_secret(load_or_create_session_key(paths, cfg)?)
}

pub(in crate::state) fn load_or_create_session_key(
    paths: &Paths,
    cfg: &RuntimeConfig,
) -> Result<Vec<u8>> {
    if let Ok(value) = std::env::var("AUTH_SESSION_SECRET")
        && !value.is_empty()
    {
        return Ok(value.into_bytes());
    }
    if !cfg.auth.session_secret.trim().is_empty() {
        return Ok(cfg.auth.session_secret.as_bytes().to_vec());
    }
    if let Some(secret) = cfg
        .toml
        .get("auth")
        .and_then(|value| value.get("session_secret"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(secret.as_bytes().to_vec());
    }
    if paths.auth_session_key.exists() || paths.auth_session_key.is_symlink() {
        return read_private(&paths.auth_session_key);
    }
    // Created 0600 from the start (no window with the umask default mode).
    let key = random_bytes::<32>().to_vec();
    write_private(&paths.auth_session_key, &key)?;
    Ok(key)
}
