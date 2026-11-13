//! Error type shared by both backends.

use std::fmt;

/// Boxed error returned by code steps (`Step::Code`).
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything the runner, the additive helpers and the snapshots can refuse.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The migration registry is malformed (empty, not contiguous, duplicate
    /// or empty names, a migration without steps).
    InvalidRegistry(String),
    /// A table, column or ledger name is not a plain SQL identifier, or an
    /// additive column definition contains a statement separator.
    InvalidIdentifier(String),
    /// The ledger table exists but cannot hold the ledger (no `version`
    /// column, or a column of an unexpected kind).
    LedgerFormat(String),
    /// An applied migration was recorded under another name.
    NameMismatch {
        /// Migration version.
        version: i64,
        /// Name in the registry of this binary.
        expected: String,
        /// Name stored in the ledger.
        found: String,
    },
    /// An applied migration no longer has the checksum it was applied with.
    ChecksumMismatch {
        /// Migration version.
        version: i64,
        /// Migration name.
        name: String,
        /// Checksum of the migration in this binary.
        expected: String,
        /// Checksum stored in the ledger.
        found: String,
    },
    /// The ledger records a checksummed version this binary does not know,
    /// inside its own version range.
    UnknownVersion(i64),
    /// The ledger records a version newer than the newest migration of this
    /// binary: the database was migrated by a newer release (downgrade).
    LedgerAhead {
        /// Highest version found in the ledger.
        found: i64,
        /// Newest migration of this binary.
        latest: i64,
    },
    /// A legacy row (version without checksum) was found and the ledger
    /// configuration does not adopt legacy rows.
    LegacyRowRejected(i64),
    /// A pending migration is older than an applied one (a migration was
    /// inserted into the middle of the registry after a newer one shipped).
    OutOfOrder {
        /// The pending migration.
        pending: i64,
        /// The newest applied migration.
        applied: i64,
    },
    /// A pinned checksum (`verify_pinned_checksums`) no longer matches.
    PinnedChecksum {
        /// Migration version.
        version: i64,
        /// The pinned (released) checksum.
        pinned: String,
        /// The checksum of the current code, or why there is none.
        actual: String,
    },
    /// SQLite `PRAGMA foreign_key_check` found violations at the end of a
    /// migration run with foreign keys off; the migration was rolled back.
    ForeignKeyViolation {
        /// Migration version.
        version: i64,
        /// Number of violating rows.
        rows: usize,
    },
    /// The SQLite and PostgreSQL schemas differ (one line per difference).
    ParityMismatch(Vec<String>),
    /// A migration precondition refused to run it (nothing was changed).
    Precondition {
        /// Migration version.
        version: i64,
        /// Migration name.
        name: String,
        /// Why the precondition refused.
        source: BoxError,
    },
    /// The SQLite connection already has an open transaction.
    TransactionInProgress,
    /// A migration step failed; the migration was rolled back.
    Step {
        /// Migration version.
        version: i64,
        /// Migration name.
        name: String,
        /// Zero-based index of the failing step.
        step: usize,
        /// Underlying error.
        source: BoxError,
    },
    /// A SQLite error outside a migration step.
    #[cfg(feature = "sqlite")]
    Sqlite(rusqlite::Error),
    /// A PostgreSQL error outside a migration step.
    #[cfg(feature = "postgres")]
    Postgres(postgres::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRegistry(detail) => write!(f, "invalid migration registry: {detail}"),
            Self::InvalidIdentifier(detail) => write!(f, "invalid SQL identifier: {detail}"),
            Self::LedgerFormat(detail) => write!(f, "unusable migration ledger: {detail}"),
            Self::NameMismatch { .. }
            | Self::ChecksumMismatch { .. }
            | Self::PinnedChecksum { .. } => self.fmt_mismatch(f),
            Self::UnknownVersion(version) => {
                write!(f, "the ledger records unknown migration {version}")
            }
            Self::LedgerAhead { found, latest } => write!(
                f,
                "the database is at migration {found}, newer than this binary ({latest}); \
                 refusing to run an older release on a newer schema"
            ),
            Self::LegacyRowRejected(version) => write!(
                f,
                "the ledger has a legacy row without checksum (version {version}) \
                 and legacy adoption is not enabled"
            ),
            Self::OutOfOrder { pending, applied } => write!(
                f,
                "migration {pending} is pending but newer migration {applied} is applied"
            ),
            Self::ForeignKeyViolation { version, rows } => write!(
                f,
                "migration {version} left {rows} foreign-key violation(s); rolled back"
            ),
            Self::ParityMismatch(diffs) => {
                write!(f, "schema parity mismatch: {}", diffs.join("; "))
            }
            Self::Precondition {
                version,
                name,
                source,
            } => write!(
                f,
                "migration {version} ({name}) precondition refused: {source}"
            ),
            Self::TransactionInProgress => {
                write!(f, "the connection already has an open transaction")
            }
            Self::Step {
                version,
                name,
                step,
                source,
            } => write!(
                f,
                "migration {version} ({name}) step {step} failed: {source}"
            ),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(error) => write!(f, "sqlite: {error}"),
            #[cfg(feature = "postgres")]
            Self::Postgres(error) => write!(f, "postgres: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Step { source, .. } | Self::Precondition { source, .. } => Some(source.as_ref()),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(error) => Some(error),
            #[cfg(feature = "postgres")]
            Self::Postgres(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[cfg(feature = "postgres")]
impl From<postgres::Error> for Error {
    fn from(error: postgres::Error) -> Self {
        Self::Postgres(error)
    }
}

impl Error {
    /// Display of the two "applied migration changed" variants.
    fn fmt_mismatch(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameMismatch {
                version,
                expected,
                found,
            } => write!(
                f,
                "migration {version} was applied as {found:?}, this binary calls it {expected:?}"
            ),
            Self::ChecksumMismatch {
                version,
                name,
                expected,
                found,
            } => write!(
                f,
                "migration {version} ({name}) differs from the applied one: \
                 checksum {found} in the ledger, {expected} in this binary"
            ),
            Self::PinnedChecksum {
                version,
                pinned,
                actual,
            } => write!(
                f,
                "migration {version} checksum is {actual}, pinned {pinned}: \
                 applied migrations are immutable; add a new migration"
            ),
            _ => Ok(()),
        }
    }
}
