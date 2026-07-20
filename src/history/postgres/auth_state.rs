use super::{rate_limit, session, session_locks};
use crate::history::RuntimeAuthState;
use anyhow::Result;
use postgres::Client;

pub(super) fn import(client: &mut Client, state: &RuntimeAuthState) -> Result<()> {
    let mut tx = client.transaction()?;

    let mut providers = state
        .sessions
        .iter()
        .filter_map(|record| {
            Some((
                record.provider_issuer.as_deref()?,
                record.provider_session_id.as_deref()?,
            ))
        })
        .collect::<Vec<_>>();
    providers.sort_unstable();
    providers.dedup();
    for (issuer, provider_session_id) in providers {
        session_locks::lock_provider_session(&mut tx, Some(issuer), Some(provider_session_id))?;
    }

    let mut users = state
        .sessions
        .iter()
        .map(|record| record.user_sub.as_str())
        .collect::<Vec<_>>();
    users.sort_unstable();
    users.dedup();
    for user in users {
        session_locks::lock_user(&mut tx, user)?;
    }

    let mut rate_keys = state
        .rate_limits
        .iter()
        .map(|record| record.key_hash.as_str())
        .collect::<Vec<_>>();
    rate_keys.sort_unstable();
    rate_keys.dedup();
    for key in rate_keys {
        rate_limit::lock_key(&mut tx, key)?;
    }

    for record in &state.sessions {
        session::import_session_locked(&mut tx, record)?;
    }
    for token in &state.logout_tokens {
        session::import_logout_token(&mut tx, token)?;
    }
    for record in &state.rate_limits {
        rate_limit::import_locked(&mut tx, record)?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{AuthRateLimitRecord, AuthSessionRecord};
    use auth_modules::rate_limit::PersistentRateLimitRecord;

    #[test]
    #[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
    fn postgres_runtime_auth_state_import_rolls_back_as_one_transaction() {
        let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
            .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
        let mut client = super::super::connect_postgres(&url, true).unwrap();
        let suffix = crate::util::random_hex(8);
        let session_id = format!("atomic-session-{suffix}");
        let rate_key = format!("atomic-rate-{suffix}");
        let function_name = format!("fail_auth_import_{suffix}");
        let trigger_name = format!("fail_auth_import_trigger_{suffix}");
        client
            .batch_execute(&format!(
                r#"
CREATE FUNCTION {function_name}() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'forced auth state import failure';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER {trigger_name}
BEFORE INSERT ON klaxond_auth_rate_limits
FOR EACH ROW
WHEN (NEW.key_hash = '{rate_key}')
EXECUTE FUNCTION {function_name}();
"#
            ))
            .unwrap();
        let state = RuntimeAuthState {
            sessions: vec![AuthSessionRecord {
                id_hash: session_id.clone(),
                family_hash: format!("family-{suffix}"),
                user_json: r#"{"sub":"atomic-user"}"#.to_string(),
                user_sub: format!("atomic-user-{suffix}"),
                auth_mode: "basic".to_string(),
                provider_issuer: None,
                provider_session_id: None,
                created_at: 1_000,
                last_seen_at: 1_000,
                last_rotated_at: 1_000,
                expires_at: 2_000,
                revoked_at: None,
            }],
            logout_tokens: Vec::new(),
            rate_limits: vec![AuthRateLimitRecord {
                key_hash: rate_key,
                state: PersistentRateLimitRecord {
                    failure_epochs: vec![1_000],
                    locked_until_epoch: None,
                },
                updated_at: 1_000,
            }],
        };

        let result = import(&mut client, &state);
        let session_count: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM klaxond_auth_sessions WHERE id_hash = $1",
                &[&session_id],
            )
            .unwrap()
            .get(0);
        client
            .batch_execute(&format!(
                "DROP TRIGGER IF EXISTS {trigger_name} ON klaxond_auth_rate_limits;\
                 DROP FUNCTION IF EXISTS {function_name}();"
            ))
            .unwrap();

        assert!(result.is_err());
        assert_eq!(session_count, 0);
    }
}
