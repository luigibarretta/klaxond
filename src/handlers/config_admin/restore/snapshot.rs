//! Pre-restore snapshots of the files a restore overwrites, written back
//! when applying the restored configuration fails.

use super::input::{RestoreInput, restore_input_would_restore};
use super::restore_path;
use crate::config::Paths;
use crate::util::atomic_write;
use crate::util::private_file::write_private;
use std::fs;
use std::path::{Path, PathBuf};

/// `auth-config.json` carries credentials and is always written 0600.
pub(super) fn write_restored(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    if private {
        write_private(path, bytes)
    } else {
        atomic_write(path, bytes)
    }
}

pub(super) struct FileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    private: bool,
}

pub(super) fn restore_file_snapshots(
    paths: &Paths,
    input: &RestoreInput,
) -> Result<Vec<FileSnapshot>, String> {
    restore_input_would_restore(input)
        .into_iter()
        .map(|name| {
            let path = restore_path(paths, name)?.to_path_buf();
            let private = path == paths.auth_config;
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("snapshot {} failed: {err}", path.display())),
            };
            Ok(FileSnapshot {
                path,
                bytes,
                private,
            })
        })
        .collect()
}

pub(super) fn restore_snapshots(snapshots: &[FileSnapshot]) -> Result<(), String> {
    let mut errors = Vec::new();
    for snapshot in snapshots {
        let result = if let Some(bytes) = snapshot.bytes.as_deref() {
            write_restored(&snapshot.path, bytes, snapshot.private).map_err(|err| err.to_string())
        } else {
            match fs::remove_file(&snapshot.path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.to_string()),
            }
        };
        if let Err(err) = result {
            errors.push(format!("{}: {err}", snapshot.path.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
