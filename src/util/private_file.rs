//! Owner-private secret files (session key, `auth-config.json`).
//!
//! Writes go through `auth_modules::secrets::files::write_private_atomic`
//! (0600 temporary file created exclusively, fsync, rename, directory fsync),
//! so the secret is never visible with the umask's default mode. Reads go
//! through `read_private_file`, which rejects symlinks, foreign owners and
//! group/other permission bits. Files written by releases before 0.23 were
//! left at the umask default (typically 0644); [`tighten_private_mode`] fixes
//! them in place before the first read.

use anyhow::{Context, Result};
use auth_modules::secrets::files::{read_private_file, write_private_atomic};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Upper bound for a private file read (the auth sidecar holds passkeys,
/// TOTP factors and API-key hashes, so it is far larger than a key).
pub const MAX_PRIVATE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Removes group/other permission bits from an existing regular file owned
/// by this process. Missing files and symlinks are left alone: the private
/// reader rejects symlinks anyway, and a missing file is created 0600.
pub fn tighten_private_mode(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return Ok(());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o700))
        .with_context(|| format!("restrict permissions of {}", path.display()))?;
    tracing::warn!(
        path = %path.display(),
        "secret file was readable by group/other (mode {mode:04o}); restricted to {:04o}",
        mode & 0o700
    );
    Ok(())
}

/// Reads a private file after tightening legacy permissions.
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    tighten_private_mode(path)?;
    read_private_file(path, MAX_PRIVATE_FILE_BYTES)
        .map(|bytes| bytes.into_inner())
        .with_context(|| format!("read private file {}", path.display()))
}

/// Atomically replaces `path` with a 0600 file, creating the parent first.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    write_private_atomic(path, bytes)
        .with_context(|| format!("write private file {}", path.display()))
}

pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_private(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_are_owner_private() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested/secret.json");
        write_private_json(&path, &serde_json::json!({"k": "v"})).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert!(read_private(&path).unwrap().starts_with(b"{"));
    }

    #[test]
    fn legacy_world_readable_files_are_tightened_before_reading() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("auth-config.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_private(&path).unwrap(), b"{}");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn symlinked_secret_files_are_rejected() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        write_private(&target, b"secret").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_private(&link).is_err());
    }
}
