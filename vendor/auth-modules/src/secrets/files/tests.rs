use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory removed on drop; avoids a tempfile dependency.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "auth-modules-secret-files-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch dir");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod dir");
        Self(path)
    }

    fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod fixture");
        path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn reads_private_regular_file() {
    let dir = ScratchDir::new();
    let path = dir.file("secret", b"top-secret\n", 0o600);
    let secret = read_private_file(&path, 64).expect("private file");
    assert_eq!(secret.expose_secret(), b"top-secret\n");
    assert_eq!(format!("{secret:?}"), "[REDACTED]");

    let path = dir.file("read-only", b"  value \r\n", 0o400);
    let secret = read_private_string(&path, 64).expect("private string");
    assert_eq!(secret.expose_secret(), "value");
}

#[test]
fn trimming_is_optional_for_bytes() {
    let dir = ScratchDir::new();
    let path = dir.file("secret", b"\tkey\n", 0o600);
    let options = PrivateFileOptions::new(64).trim_ascii_whitespace();
    let secret = read_private_file_with(&path, &options).expect("trimmed bytes");
    assert_eq!(secret.expose_secret(), b"key");
}

#[test]
fn rejects_group_or_other_permissions() {
    let dir = ScratchDir::new();
    for mode in [0o640, 0o604, 0o660, 0o644, 0o610] {
        let path = dir.file(&format!("shared-{mode:o}"), b"value", mode);
        let error = read_private_file(&path, 64).expect_err("shared file");
        assert!(
            matches!(error, PrivateFileError::InsecurePermissions { .. }),
            "{mode:o}: {error}"
        );
    }
}

#[test]
fn rejects_symlinks_even_to_private_files() {
    let dir = ScratchDir::new();
    let target = dir.file("target", b"value", 0o600);
    let link = dir.0.join("link");
    symlink(&target, &link).expect("symlink");
    let error = read_private_file(&link, 64).expect_err("symlink");
    assert!(matches!(error, PrivateFileError::Symlink), "{error}");
}

#[test]
fn rejects_non_regular_files() {
    let dir = ScratchDir::new();
    let nested = dir.0.join("nested");
    fs::create_dir(&nested).expect("dir");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).expect("chmod");
    let error = read_private_file(&nested, 64).expect_err("directory");
    assert!(matches!(error, PrivateFileError::NotRegularFile), "{error}");
}

#[test]
fn enforces_the_size_limit() {
    let dir = ScratchDir::new();
    let path = dir.file("secret", b"0123456789", 0o600);
    assert!(read_private_file(&path, 10).is_ok());
    let error = read_private_file(&path, 9).expect_err("too large");
    assert!(matches!(error, PrivateFileError::TooLarge { max_bytes: 9 }));
}

#[test]
fn enforces_the_owner_policy() {
    let dir = ScratchDir::new();
    let path = dir.file("secret", b"value", 0o600);
    let owner = fs::metadata(&path).expect("metadata").uid();
    let other = PrivateFileOptions::new(64).owner(FileOwner::Uid(owner.wrapping_add(1)));
    let error = read_private_file_with(&path, &other).expect_err("wrong owner");
    assert!(
        matches!(error, PrivateFileError::WrongOwner { .. }),
        "{error}"
    );

    let exact = PrivateFileOptions::new(64).owner(FileOwner::Uid(owner));
    assert!(read_private_file_with(&path, &exact).is_ok());
    let any = PrivateFileOptions::new(64).owner(FileOwner::Any);
    assert!(read_private_file_with(&path, &any).is_ok());
}

#[test]
fn rejects_empty_and_non_utf8_secrets() {
    let dir = ScratchDir::new();
    let blank = dir.file("blank", b" \n", 0o600);
    let error = read_private_string(&blank, 64).expect_err("blank");
    assert!(matches!(error, PrivateFileError::Empty), "{error}");

    let binary = dir.file("binary", b"\xff\xfe", 0o600);
    let error = read_private_string(&binary, 64).expect_err("binary");
    assert!(matches!(error, PrivateFileError::NotUtf8), "{error}");
}

#[test]
fn missing_files_report_io_errors() {
    let dir = ScratchDir::new();
    let error = read_private_file(dir.0.join("absent"), 64).expect_err("missing");
    assert!(matches!(error, PrivateFileError::Io(_)), "{error}");
}

#[test]
fn atomic_write_creates_private_file_without_leftovers() {
    let dir = ScratchDir::new();
    let path = dir.0.join("state.json");
    write_private_atomic(&path, b"first").expect("first write");
    write_private_atomic(&path, b"second").expect("second write");

    assert_eq!(fs::read(&path).expect("read back"), b"second");
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        read_private_file(&path, 64)
            .expect("readable")
            .expose_secret(),
        b"second"
    );
    let entries = fs::read_dir(&dir.0).expect("list").count();
    assert_eq!(entries, 1, "temporary files must not remain");
}

#[test]
fn atomic_write_replaces_a_symlink_instead_of_following_it() {
    let dir = ScratchDir::new();
    let victim = dir.file("victim", b"untouched", 0o644);
    let path = dir.0.join("secret");
    symlink(&victim, &path).expect("symlink");

    write_private_atomic(&path, b"new").expect("write");

    assert_eq!(fs::read(&victim).expect("victim"), b"untouched");
    assert!(!fs::symlink_metadata(&path)
        .expect("metadata")
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&path).expect("secret"), b"new");
}

#[test]
fn atomic_write_rejects_paths_without_a_file_name() {
    let error = write_private_atomic("/", b"x").expect_err("root");
    assert!(matches!(error, PrivateFileError::InvalidPath), "{error}");
}

#[test]
fn identity_check_detects_a_replaced_file() {
    let dir = ScratchDir::new();
    let first = dir.file("first", b"a", 0o600);
    let second = dir.file("second", b"b", 0o600);
    let first = fs::symlink_metadata(first).expect("first");
    let second = fs::symlink_metadata(second).expect("second");
    assert!(ensure_same_file(&first, &first).is_ok());
    let error = ensure_same_file(&first, &second).expect_err("different inode");
    assert!(matches!(error, PrivateFileError::Changed), "{error}");
}
