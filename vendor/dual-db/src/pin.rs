//! Pinned checksums: the consumer's guard against editing an applied
//! migration.
//!
//! A consumer's own tests compute expected checksums from the current code,
//! so a byte change in an applied migration (a comment, trailing whitespace,
//! CRLF line endings from `core.autocrlf`, a reordered additive column)
//! passes them, and every upgraded database then refuses to start with
//! `ChecksumMismatch`. Pin the checksum each released migration produced and
//! check it in a test:
//!
//! ```
//! # type Step = fn();
//! let migrations = vec![dual_db::Migration::<Step>::new(1, "baseline").sql("SELECT 1")];
//! dual_db::verify_pinned_checksums(
//!     &migrations,
//!     &[(1, "e004ebd5b5532a4b85984a62f8ad48a81aa3460c1ca07701f386135d72cdecf5")],
//! )
//! .unwrap();
//! ```

use crate::error::{Error, Result};
use crate::migration::Migration;

/// Checks every `(version, checksum)` pin against the registry. A pinned
/// version that is missing, or whose checksum differs, is an error whose
/// message says that applied migrations are immutable. Migrations without a
/// pin (not yet released) are not checked.
pub fn verify_pinned_checksums<F>(
    migrations: &[Migration<F>],
    pinned: &[(i64, &str)],
) -> Result<()> {
    for (version, expected) in pinned {
        let Some(migration) = migrations.iter().find(|m| m.version() == *version) else {
            return Err(Error::PinnedChecksum {
                version: *version,
                pinned: (*expected).to_owned(),
                actual: "missing from the registry".to_owned(),
            });
        };
        let actual = migration.checksum();
        if actual != *expected {
            return Err(Error::PinnedChecksum {
                version: *version,
                pinned: (*expected).to_owned(),
                actual,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type M = Migration<fn()>;

    #[test]
    fn pins_match_or_explain_immutability() {
        let migrations = vec![
            M::new(1, "a").sql("SELECT 1"),
            M::new(2, "b").sql("SELECT 2"),
        ];
        let one = migrations[0].checksum();
        assert!(verify_pinned_checksums(&migrations, &[(1, one.as_str())]).is_ok());
        assert!(verify_pinned_checksums(&migrations, &[]).is_ok());
        let error = verify_pinned_checksums(&migrations, &[(2, one.as_str())]).unwrap_err();
        assert!(matches!(error, Error::PinnedChecksum { version: 2, .. }));
        assert!(error
            .to_string()
            .contains("applied migrations are immutable; add a new migration"));
        let missing = verify_pinned_checksums(&migrations, &[(3, one.as_str())]).unwrap_err();
        assert!(missing.to_string().contains("missing from the registry"));
    }
}
