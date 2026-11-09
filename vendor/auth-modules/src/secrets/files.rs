//! Reading and writing owner-private secret files on Unix.
//!
//! [`read_private_file`] refuses symlinks, non-regular files, any group or
//! other permission bit, files owned by another user and files larger than
//! the caller's limit. The path is checked with `lstat`, opened, checked again
//! with `fstat`, and re-checked after the read; the device/inode identity must
//! be identical at every step, so swapping the path for a symlink or another
//! file between checks is detected without `O_NOFOLLOW` (which `std` cannot
//! express portably without `unsafe`/`libc`).
//!
//! The owner check needs the effective UID. Without `unsafe` it is read from
//! the owner of `/proc/self`, which Linux sets to the process's effective UID
//! for every dumpable process. Where `/proc` is unavailable (non-Linux, or a
//! non-dumpable set-UID process whose `/proc/self` is owned by root) the
//! default [`FileOwner::CurrentProcess`] policy fails closed; pass an explicit
//! [`FileOwner::Uid`] instead.
//!
//! Residual risk: if an attacker can write to the containing directory they
//! can race a FIFO into place and make `open` block. Such an attacker can
//! already replace the secret, so private directories remain a prerequisite.

use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::Redacted;

mod error;

pub use error::PrivateFileError;

/// Expected owner of a private file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FileOwner {
    /// The effective UID of this process (resolved through `/proc/self`).
    #[default]
    CurrentProcess,
    Uid(u32),
    /// Skip the owner check; permissions and type are still enforced.
    Any,
}

/// Limits and post-processing for [`read_private_file_with`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateFileOptions {
    max_bytes: u64,
    owner: FileOwner,
    trim: bool,
}

impl PrivateFileOptions {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            owner: FileOwner::CurrentProcess,
            trim: false,
        }
    }

    pub fn owner(mut self, owner: FileOwner) -> Self {
        self.owner = owner;
        self
    }

    /// Removes leading and trailing ASCII whitespace (such as the newline
    /// most editors append).
    pub fn trim_ascii_whitespace(mut self) -> Self {
        self.trim = true;
        self
    }
}

/// Reads a private file verbatim. Empty files are rejected.
pub fn read_private_file(
    path: impl AsRef<Path>,
    max_bytes: u64,
) -> Result<Redacted<Vec<u8>>, PrivateFileError> {
    read_private_file_with(path, &PrivateFileOptions::new(max_bytes))
}

/// Reads a private UTF-8 file with surrounding ASCII whitespace trimmed.
pub fn read_private_string(
    path: impl AsRef<Path>,
    max_bytes: u64,
) -> Result<Redacted<String>, PrivateFileError> {
    read_private_string_with(
        path,
        &PrivateFileOptions::new(max_bytes).trim_ascii_whitespace(),
    )
}

pub fn read_private_string_with(
    path: impl AsRef<Path>,
    options: &PrivateFileOptions,
) -> Result<Redacted<String>, PrivateFileError> {
    let bytes = read_private_file_with(path, options)?.into_inner();
    String::from_utf8(bytes)
        .map(Redacted::new)
        .map_err(|error| {
            wipe(&mut error.into_bytes());
            PrivateFileError::NotUtf8
        })
}

pub fn read_private_file_with(
    path: impl AsRef<Path>,
    options: &PrivateFileOptions,
) -> Result<Redacted<Vec<u8>>, PrivateFileError> {
    let path = path.as_ref();
    let expected_owner = resolve_owner(options.owner)?;
    let before = fs::symlink_metadata(path)?;
    validate(&before, options.max_bytes, expected_owner)?;
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    // Identity first: after a race, never report the replacement's mode/uid.
    ensure_same_file(&before, &opened)?;
    validate(&opened, options.max_bytes, expected_owner)?;

    let mut bytes = Vec::new();
    let read = (&mut file)
        .take(options.max_bytes.saturating_add(1))
        .read_to_end(&mut bytes);
    let after = fs::symlink_metadata(path);
    let outcome = read.map_err(PrivateFileError::from).and_then(|_| {
        if bytes.len() as u64 > options.max_bytes {
            return Err(PrivateFileError::TooLarge {
                max_bytes: options.max_bytes,
            });
        }
        ensure_same_file(&opened, &after?)
    });
    if let Err(error) = outcome {
        wipe(&mut bytes);
        return Err(error);
    }
    if options.trim {
        trim_in_place(&mut bytes);
    }
    if bytes.is_empty() {
        return Err(PrivateFileError::Empty);
    }
    Ok(Redacted::new(bytes))
}

/// Atomically replaces `path` with a new 0600 file containing `bytes`.
///
/// The data is written to a fresh temporary file in the same directory
/// (`create_new`, so an existing path or planted symlink is never opened),
/// synced, renamed over `path`, and the directory is synced so the rename
/// survives a crash. A symlink at `path` is replaced, not followed.
pub fn write_private_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), PrivateFileError> {
    let path = path.as_ref();
    let name = path.file_name().ok_or(PrivateFileError::InvalidPath)?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".tmp-{}", unique_suffix()));
    let temporary = parent.join(temporary_name);

    // `create_new` fails if the name exists, so a failure here leaves any
    // pre-existing entry (possibly planted by someone else) untouched.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    // From here on the temporary file is ours and must not outlive an error.
    let result = write_synced(file, bytes).and_then(|()| {
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(PrivateFileError::from)
}

fn write_synced(mut file: File, bytes: &[u8]) -> io::Result<()> {
    // The creation mode is subject to the umask; make the result exact.
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}", std::process::id())
}

fn resolve_owner(owner: FileOwner) -> Result<Option<u32>, PrivateFileError> {
    match owner {
        FileOwner::Any => Ok(None),
        FileOwner::Uid(uid) => Ok(Some(uid)),
        FileOwner::CurrentProcess => fs::metadata("/proc/self")
            .map(|metadata| Some(metadata.uid()))
            .map_err(|_| PrivateFileError::OwnerUnknown),
    }
}

fn validate(
    metadata: &Metadata,
    max_bytes: u64,
    expected_owner: Option<u32>,
) -> Result<(), PrivateFileError> {
    if metadata.file_type().is_symlink() {
        return Err(PrivateFileError::Symlink);
    }
    if !metadata.file_type().is_file() {
        return Err(PrivateFileError::NotRegularFile);
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(PrivateFileError::InsecurePermissions { mode });
    }
    if let Some(expected) = expected_owner.filter(|uid| *uid != metadata.uid()) {
        return Err(PrivateFileError::WrongOwner {
            owner: metadata.uid(),
            expected,
        });
    }
    if metadata.len() > max_bytes {
        return Err(PrivateFileError::TooLarge { max_bytes });
    }
    Ok(())
}

fn ensure_same_file(left: &Metadata, right: &Metadata) -> Result<(), PrivateFileError> {
    if left.dev() == right.dev() && left.ino() == right.ino() {
        Ok(())
    } else {
        Err(PrivateFileError::Changed)
    }
}

fn trim_in_place(bytes: &mut Vec<u8>) {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    bytes.copy_within(start..end, 0);
    let len = end - start;
    wipe(&mut bytes[len..]);
    bytes.truncate(len);
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
}

#[cfg(test)]
mod tests;
