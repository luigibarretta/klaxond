use crate::config::{Paths, RuntimeConfig};
use crate::util::{atomic_write, random_bytes};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

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
    if paths.auth_session_key.exists() {
        return fs::read(&paths.auth_session_key)
            .with_context(|| format!("read {}", paths.auth_session_key.display()));
    }
    let key = random_bytes::<32>().to_vec();
    if let Some(parent) = paths.auth_session_key.parent() {
        fs::create_dir_all(parent).ok();
    }
    atomic_write(&paths.auth_session_key, &key)?;
    set_private_mode(&paths.auth_session_key);
    Ok(key)
}

#[cfg(unix)]
fn set_private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path) {}
