//! Refuses transaction-control statements inside `Step::Sql`.
//!
//! The runner owns the transaction of every migration; a `COMMIT`,
//! `ROLLBACK`, `BEGIN`, `END`, `SAVEPOINT`, `RELEASE`, `START` or `ABORT`
//! in a step would end it early and break atomicity and the ledger. The
//! scan understands `'…'` strings, `"…"` identifiers, `$tag$…$tag$` bodies,
//! `--` and `/* */` comments, and SQLite trigger bodies
//! (`CREATE TRIGGER … BEGIN … END`), so the keywords inside them are fine.

use crate::error::{Error, Result};

const FORBIDDEN: &[&str] = &[
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT",
    "RELEASE",
    "END",
    "START",
    "ABORT",
];

/// Errors when a top-level statement of `sql` is a transaction-control one.
pub(crate) fn reject_transaction_control(sql: &str) -> Result<()> {
    let mut in_trigger = false;
    for statement in split_statements(sql) {
        let words = leading_words(&statement, 3);
        let Some(first) = words.first() else {
            continue;
        };
        if in_trigger {
            if first == "END" {
                in_trigger = false;
            }
            continue;
        }
        if first == "CREATE" && words.iter().skip(1).any(|word| word == "TRIGGER") {
            in_trigger = true;
            continue;
        }
        if FORBIDDEN.contains(&first.as_str()) {
            return Err(Error::InvalidRegistry(format!(
                "SQL step contains a transaction-control statement ({first}); \
                 the runner owns the migration transaction"
            )));
        }
    }
    Ok(())
}

/// Splits on top-level `;`, dropping comments and keeping quoted text.
fn split_statements(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        i = match (c, next) {
            ('-', Some('-')) => skip_until(&chars, i, "\n"),
            ('/', Some('*')) => skip_until(&chars, i + 2, "*/"),
            ('\'', _) | ('"', _) => copy_quoted(&chars, i, c, &mut current),
            ('$', _) => copy_dollar(&chars, i, &mut current),
            (';', _) => {
                statements.push(std::mem::take(&mut current));
                i + 1
            }
            _ => {
                current.push(c);
                i + 1
            }
        };
    }
    statements.push(current);
    statements
}

fn skip_until(chars: &[char], start: usize, end: &str) -> usize {
    let end: Vec<char> = end.chars().collect();
    let mut i = start;
    while i < chars.len() {
        if chars.get(i..i + end.len()) == Some(end.as_slice()) {
            return i + end.len();
        }
        i += 1;
    }
    chars.len()
}

fn copy_quoted(chars: &[char], start: usize, quote: char, out: &mut String) -> usize {
    out.push(' ');
    let mut i = start + 1;
    while let Some(&c) = chars.get(i) {
        i += 1;
        if c == quote {
            if chars.get(i) == Some(&quote) {
                i += 1;
                continue;
            }
            break;
        }
    }
    out.push(' ');
    i
}

/// `$tag$ … $tag$` (PostgreSQL); a lone `$1` parameter is copied as is.
fn copy_dollar(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut j = start + 1;
    while chars
        .get(j)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        j += 1;
    }
    let tag_is_valid =
        chars.get(j) == Some(&'$') && chars.get(start + 1).is_none_or(|c| !c.is_ascii_digit());
    if !tag_is_valid {
        out.push('$');
        return start + 1;
    }
    let tag: String = chars
        .get(start..=j)
        .map(|t| t.iter().collect())
        .unwrap_or_default();
    out.push(' ');
    skip_until(chars, j + 1, &tag)
}

fn leading_words(statement: &str, count: usize) -> Vec<String> {
    statement
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .take(count)
        .map(str::to_ascii_uppercase)
        .collect()
}

#[cfg(test)]
#[path = "sql_guard_tests.rs"]
mod tests;
