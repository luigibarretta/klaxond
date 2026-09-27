use crate::config::HistoryConfig;
use anyhow::{Result, bail};
use std::sync::{Mutex, MutexGuard};

mod delivery;
pub mod emergency;
mod emergency_store;
mod migration;
mod postgres;
mod rate_limit;
mod repeat;
mod session;
mod session_store;
mod sqlite;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use delivery::approximate_delivery_bytes;
pub(crate) use delivery::{APPROXIMATE_DELIVERY_ROW_OVERHEAD, dedupe_hash, delivery_search_values};
pub use delivery::{
    DeliveryActivity, DeliveryEntry, DeliveryPage, DeliveryQuery, MAX_DELIVERY_QUERY_CHARS,
    SuppressedFilter,
};
pub use emergency::{
    EmergencyAttempt, EmergencyCandidate, EmergencyChannelSnapshot, EmergencyIncident,
    EmergencyPayload, EmergencyPolicySnapshot, EmergencyRegistration,
};
pub(crate) use migration::snapshot_runtime_auth_state;
pub use migration::{migrate_between, run_migrate_cli};
use postgres::PostgresWorker;
pub use rate_limit::AuthRateLimitRecord;
pub use repeat::{
    RepeatCandidate, RepeatDecision, RepeatState, RepeatSuppressionReason, RepeatSuppressionSummary,
};
pub use session::{AuthSessionRecord, OidcLogoutResult, OidcLogoutTokenRecord};
use sqlite::{
    SqliteConnection, migrate_sqlite, open_sqlite, sqlite_delivery_activity, sqlite_delivery_count,
    sqlite_delivery_page, sqlite_export_all, sqlite_insert, sqlite_prune, validate_sqlite_schema,
};

const SCHEMA_VERSION: i64 = 9;

pub struct HistoryStore {
    backend: HistoryBackend,
    retention: usize,
}

#[derive(Clone)]
pub(crate) struct RuntimeAuthState {
    pub(crate) sessions: Vec<AuthSessionRecord>,
    pub(crate) logout_tokens: Vec<OidcLogoutTokenRecord>,
    pub(crate) rate_limits: Vec<AuthRateLimitRecord>,
}

enum HistoryBackend {
    Sqlite(Mutex<SqliteConnection>),
    Postgres(PostgresWorker),
}

impl HistoryStore {
    pub fn open(cfg: &HistoryConfig) -> Result<Self> {
        Self::open_with_mode(cfg, true)
    }

    fn open_existing(cfg: &HistoryConfig) -> Result<Self> {
        Self::open_with_mode(cfg, false)
    }

    fn open_with_mode(cfg: &HistoryConfig, create_schema: bool) -> Result<Self> {
        let retention = cfg.retention;
        let backend = match cfg.backend.as_str() {
            "sqlite" => {
                let conn = open_sqlite(&cfg.sqlite_path, create_schema)?;
                if create_schema {
                    migrate_sqlite(&conn)?;
                } else {
                    validate_sqlite_schema(&conn)?;
                }
                HistoryBackend::Sqlite(Mutex::new(conn))
            }
            "postgres" | "postgresql" => {
                if cfg.postgres_url.trim().is_empty() {
                    bail!("history backend is postgres but KLAXOND_POSTGRES_URL is empty");
                }
                HistoryBackend::Postgres(PostgresWorker::start(
                    cfg.postgres_url.clone(),
                    retention,
                    create_schema,
                )?)
            }
            other => bail!("unsupported history backend {other:?}; use sqlite or postgres"),
        };
        Ok(Self { backend, retention })
    }

    pub fn record_delivery(&self, entry: &DeliveryEntry) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                sqlite_insert(&conn, entry)?;
                sqlite_prune(&conn, self.retention)?;
            }
            HistoryBackend::Postgres(worker) => {
                worker.record_delivery(entry)?;
            }
        }
        Ok(())
    }

    pub fn deliveries_page(&self, limit: usize, offset: usize) -> Result<DeliveryPage> {
        self.query_deliveries(&DeliveryQuery::page(limit, offset))
    }

    pub fn query_deliveries(&self, query: &DeliveryQuery) -> Result<DeliveryPage> {
        let query = query.normalized();
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                let total = sqlite_delivery_count(&conn, &query)?;
                let entries = sqlite_delivery_page(&conn, &query)?;
                Ok(DeliveryPage {
                    entries,
                    total,
                    limit: query.limit,
                    offset: query.offset,
                })
            }
            HistoryBackend::Postgres(worker) => worker.query_deliveries(&query),
        }
    }

    pub fn delivery_activity(
        &self,
        hours: u16,
        since: f64,
        until: f64,
    ) -> Result<DeliveryActivity> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite_delivery_activity(
                &lock(conn, "sqlite history connection"),
                hours,
                since,
                until,
            ),
            HistoryBackend::Postgres(worker) => worker.delivery_activity(hours, since, until),
        }
    }

    pub fn export_all(&self) -> Result<Vec<DeliveryEntry>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let mut conn = lock(conn, "sqlite history connection");
                sqlite_export_all(&mut conn)
            }
            HistoryBackend::Postgres(worker) => worker.export_all(),
        }
    }

    pub fn reserve_repeat(&self, candidate: &RepeatCandidate) -> Result<RepeatDecision> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let mut conn = lock(conn, "sqlite history connection");
                sqlite::repeat::reserve(&mut conn, candidate)
            }
            HistoryBackend::Postgres(worker) => worker.reserve_repeat(candidate),
        }
    }

    pub fn complete_repeat(
        &self,
        fingerprint: &str,
        reservation_token: &str,
        delivered_at: Option<f64>,
    ) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                sqlite::repeat::complete(&conn, fingerprint, reservation_token, delivered_at)
            }
            HistoryBackend::Postgres(worker) => {
                worker.complete_repeat(fingerprint, reservation_token, delivered_at)
            }
        }
    }

    pub fn recent_repeat_suppressions(
        &self,
        limit: usize,
    ) -> Result<Vec<RepeatSuppressionSummary>> {
        let states = match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                sqlite::repeat::recent_suppressions(&conn, limit.clamp(1, 1_000))?
            }
            HistoryBackend::Postgres(worker) => {
                worker.recent_repeat_suppressions(limit.clamp(1, 1_000))?
            }
        };
        Ok(states
            .into_iter()
            .filter_map(RepeatState::summary)
            .collect())
    }

    fn export_repeat_states(&self) -> Result<Vec<RepeatState>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                sqlite::repeat::export_all(&conn)
            }
            HistoryBackend::Postgres(worker) => worker.export_repeat_states(),
        }
    }

    fn import_repeat_state(&self, state: &RepeatState) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                sqlite::repeat::import(&conn, state)
            }
            HistoryBackend::Postgres(worker) => worker.import_repeat_state(state),
        }
    }

    pub fn auth_rate_limited(&self, key_hash: &str, now: i64) -> Result<bool> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::rate_limit::limited(
                &mut lock(conn, "sqlite history connection"),
                key_hash,
                now,
            ),
            HistoryBackend::Postgres(worker) => worker.auth_rate_limited(key_hash, now),
        }
    }

    pub fn record_auth_failure(&self, key_hash: &str, now: i64) -> Result<bool> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => sqlite::rate_limit::record_failure(
                &mut lock(conn, "sqlite history connection"),
                key_hash,
                now,
            ),
            HistoryBackend::Postgres(worker) => worker.record_auth_failure(key_hash, now),
        }
    }

    pub fn clear_auth_failures(&self, key_hash: &str) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::rate_limit::clear(&lock(conn, "sqlite history connection"), key_hash)
            }
            HistoryBackend::Postgres(worker) => worker.clear_auth_failures(key_hash),
        }
    }

    fn export_auth_sessions(&self) -> Result<Vec<AuthSessionRecord>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::session::export_sessions(&lock(conn, "sqlite history connection"))
            }
            HistoryBackend::Postgres(worker) => worker.export_auth_sessions(),
        }
    }

    fn export_oidc_logout_tokens(&self) -> Result<Vec<OidcLogoutTokenRecord>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::session::export_logout_tokens(&lock(conn, "sqlite history connection"))
            }
            HistoryBackend::Postgres(worker) => worker.export_oidc_logout_tokens(),
        }
    }

    fn export_auth_rate_limits(&self) -> Result<Vec<AuthRateLimitRecord>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::rate_limit::export_all(&lock(conn, "sqlite history connection"))
            }
            HistoryBackend::Postgres(worker) => worker.export_auth_rate_limits(),
        }
    }

    pub(crate) fn import_runtime_auth_state(&self, state: &RuntimeAuthState) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                sqlite::auth_state::import(&mut lock(conn, "sqlite history connection"), state)
            }
            HistoryBackend::Postgres(worker) => worker.import_runtime_auth_state(state),
        }
    }
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        tracing::error!("recovering poisoned mutex: {name}");
        poisoned.into_inner()
    })
}
