use super::{
    AuthSessionRecord, HistoryBackend, HistoryStore, OidcLogoutResult, OidcLogoutTokenRecord, lock,
    sqlite,
};
use anyhow::Result;

impl HistoryStore {
    pub fn create_auth_session(
        &self,
        record: &AuthSessionRecord,
        replace_id_hash: Option<&str>,
        max_concurrent: usize,
        now: i64,
    ) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::session::create(
                &mut lock(conn, "sqlite history connection"),
                record,
                replace_id_hash,
                max_concurrent,
                now,
            ),
            HistoryBackend::Postgres(worker) => {
                worker.create_auth_session(record, replace_id_hash, max_concurrent, now)
            }
        }
    }

    pub fn auth_session(
        &self,
        id_hash: &str,
        now: i64,
        idle_timeout_seconds: i64,
    ) -> Result<Option<AuthSessionRecord>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::session::lookup(
                &mut lock(conn, "sqlite history connection"),
                id_hash,
                now,
                idle_timeout_seconds,
            ),
            HistoryBackend::Postgres(worker) => {
                worker.auth_session(id_hash, now, idle_timeout_seconds)
            }
        }
    }

    pub fn auth_session_rotation_successor(
        &self,
        predecessor_hash: &str,
        successor_hash: &str,
        now: i64,
        idle_timeout_seconds: i64,
    ) -> Result<Option<AuthSessionRecord>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::session::lookup_rotation_successor(
                &mut lock(conn, "sqlite history connection"),
                predecessor_hash,
                successor_hash,
                now,
                idle_timeout_seconds,
            ),
            HistoryBackend::Postgres(worker) => worker.auth_session_rotation_successor(
                predecessor_hash,
                successor_hash,
                now,
                idle_timeout_seconds,
            ),
        }
    }

    pub fn revoke_auth_session(&self, id_hash: &str, now: i64) -> Result<bool> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::session::revoke(&lock(conn, "sqlite history connection"), id_hash, now)
            }
            HistoryBackend::Postgres(worker) => worker.revoke_auth_session(id_hash, now),
        }
    }

    pub fn revoke_auth_session_family(&self, id_hash: &str, now: i64) -> Result<usize> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::session::revoke_family_by_id(
                &mut lock(conn, "sqlite history connection"),
                id_hash,
                now,
            ),
            HistoryBackend::Postgres(worker) => worker.revoke_auth_session_family(id_hash, now),
        }
    }

    pub fn consume_oidc_logout(
        &self,
        token: &OidcLogoutTokenRecord,
        provider_session_id: Option<&str>,
        subject: Option<&str>,
        now: i64,
    ) -> Result<OidcLogoutResult> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::session::consume_oidc_logout(
                &mut lock(conn, "sqlite history connection"),
                token,
                provider_session_id,
                subject,
                now,
            ),
            HistoryBackend::Postgres(worker) => {
                worker.consume_oidc_logout(token, provider_session_id, subject, now)
            }
        }
    }
}
