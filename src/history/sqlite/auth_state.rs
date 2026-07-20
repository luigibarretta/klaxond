use crate::history::{RuntimeAuthState, sqlite};
use anyhow::Result;
use rusqlite::{Connection, TransactionBehavior};

pub(in crate::history) fn import(conn: &mut Connection, state: &RuntimeAuthState) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for session in &state.sessions {
        sqlite::session::import_session(&tx, session)?;
    }
    for token in &state.logout_tokens {
        sqlite::session::import_logout_token(&tx, token)?;
    }
    for record in &state.rate_limits {
        sqlite::rate_limit::import_in_transaction(&tx, record)?;
    }
    tx.commit()?;
    Ok(())
}
