use anyhow::Result;
use postgres::Transaction;

const LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))";

pub(super) fn lock_user(tx: &mut Transaction<'_>, user_sub: &str) -> Result<()> {
    const LOCK_SEED: i64 = 5_426_893_470_587_711_022;
    tx.query_one(LOCK_SQL, &[&user_sub, &LOCK_SEED])?;
    Ok(())
}

pub(super) fn lock_provider_session(
    tx: &mut Transaction<'_>,
    issuer: Option<&str>,
    provider_session_id: Option<&str>,
) -> Result<()> {
    const LOCK_SEED: i64 = 7_435_305_156_156_316_549;
    let (Some(issuer), Some(provider_session_id)) = (issuer, provider_session_id) else {
        return Ok(());
    };
    let key = format!("{issuer}\u{1f}{provider_session_id}");
    tx.query_one(LOCK_SQL, &[&key, &LOCK_SEED])?;
    Ok(())
}

pub(super) fn lock_oidc_users(
    tx: &mut Transaction<'_>,
    issuer: &str,
    provider_session_id: Option<&str>,
    subject: Option<&str>,
) -> Result<()> {
    let mut subjects = if let Some(subject) = subject {
        vec![subject.to_string()]
    } else if let Some(provider_session_id) = provider_session_id {
        tx.query(
            r#"
SELECT DISTINCT user_sub
FROM klaxond_auth_sessions
WHERE auth_mode = 'oidc' AND provider_issuer = $1
  AND provider_session_id = $2 AND revoked_at IS NULL
ORDER BY user_sub
"#,
            &[&issuer, &provider_session_id],
        )?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
    } else {
        Vec::new()
    };
    subjects.sort_unstable();
    subjects.dedup();
    for subject in subjects {
        lock_user(tx, &subject)?;
    }
    Ok(())
}
