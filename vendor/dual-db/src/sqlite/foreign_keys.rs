//! Foreign-key enforcement around SQLite migrations that rebuild tables.

use super::Migration;
use crate::error::{Error, Result};
use rusqlite::Connection;

/// Fails closed when the migration left any foreign-key violation.
pub(super) fn check_foreign_keys(conn: &Connection, migration: &Migration) -> Result<()> {
    let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    let mut count = 0usize;
    while rows.next()?.is_some() {
        count += 1;
    }
    if count > 0 {
        return Err(Error::ForeignKeyViolation {
            version: migration.version(),
            rows: count,
        });
    }
    Ok(())
}

/// Foreign-key enforcement switched off for a migration and restored after
/// it (also on drop, when the run ends with an error).
pub(super) struct ForeignKeys<'c> {
    conn: &'c Connection,
    off: bool,
    switched_off_here: bool,
}

impl<'c> ForeignKeys<'c> {
    pub(super) fn new(conn: &'c Connection) -> Self {
        Self {
            conn,
            off: false,
            switched_off_here: false,
        }
    }

    pub(super) fn disabled(&self) -> bool {
        self.off
    }

    pub(super) fn set_disabled(&mut self, off: bool) -> Result<()> {
        if off {
            let enforced: i64 = self
                .conn
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
            if enforced != 0 {
                self.conn.execute_batch("PRAGMA foreign_keys = OFF")?;
                self.switched_off_here = true;
            }
            self.off = true;
            return Ok(());
        }
        self.restore()
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        if self.switched_off_here {
            self.conn.execute_batch("PRAGMA foreign_keys = ON")?;
            self.switched_off_here = false;
        }
        self.off = false;
        Ok(())
    }
}

impl Drop for ForeignKeys<'_> {
    fn drop(&mut self) {
        if self.switched_off_here && self.conn.is_autocommit() {
            // Best effort: the original error is what the caller reports.
            let _ = self.conn.execute_batch("PRAGMA foreign_keys = ON");
        }
    }
}
