use super::{HistoryBackend, HistoryStore, lock};
use crate::history::{
    EmergencyAttempt, EmergencyCandidate, EmergencyIncident, EmergencyRegistration,
};
use anyhow::Result;

impl HistoryStore {
    pub fn emergency_register(
        &self,
        candidate: &EmergencyCandidate,
    ) -> Result<EmergencyRegistration> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::register(
                &mut lock(conn, "sqlite history connection"),
                candidate,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_register(candidate),
        }
    }

    pub fn emergency_initial_attempt(&self, attempt: &EmergencyAttempt) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::record_initial_attempt(
                &lock(conn, "sqlite history connection"),
                attempt,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_initial_attempt(attempt),
        }
    }

    pub fn emergency_reserve_due(
        &self,
        now: f64,
        lease_until: f64,
        token: &str,
    ) -> Result<Option<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::reserve_due(
                &mut lock(conn, "sqlite history connection"),
                now,
                lease_until,
                token,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_reserve(now, lease_until, token),
        }
    }

    pub fn emergency_complete_attempt(&self, attempt: &EmergencyAttempt) -> Result<bool> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::complete_attempt(
                &lock(conn, "sqlite history connection"),
                attempt,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_complete(attempt),
        }
    }

    pub fn emergency_terminalize(
        &self,
        receipt: &str,
        state: &str,
        actor: &str,
        now: f64,
    ) -> Result<Option<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::terminalize(
                &lock(conn, "sqlite history connection"),
                receipt,
                state,
                actor,
                now,
            ),
            HistoryBackend::Postgres(worker) => {
                worker.emergency_terminalize(receipt, state, actor, now)
            }
        }
    }

    pub fn emergency_terminalize_fingerprint(
        &self,
        fingerprint: &str,
        state: &str,
        actor: &str,
        now: f64,
    ) -> Result<Option<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::terminalize_fingerprint(
                &lock(conn, "sqlite history connection"),
                fingerprint,
                state,
                actor,
                now,
            ),
            HistoryBackend::Postgres(worker) => {
                worker.emergency_terminalize_fingerprint(fingerprint, state, actor, now)
            }
        }
    }

    pub fn emergency_expire_due(&self, now: f64, limit: usize) -> Result<Vec<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::expire_due(
                &mut lock(conn, "sqlite history connection"),
                now,
                limit,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_expire(now, limit),
        }
    }

    pub fn emergency_retry_now(&self, receipt: &str, now: f64) -> Result<bool> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::retry_now(
                &lock(conn, "sqlite history connection"),
                receipt,
                now,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_retry(receipt, now),
        }
    }

    pub fn emergency_get(&self, receipt: &str) -> Result<Option<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                super::sqlite::emergency::get(&lock(conn, "sqlite history connection"), receipt)
            }
            HistoryBackend::Postgres(worker) => worker.emergency_get(receipt),
        }
    }

    pub fn emergencies(&self, state: Option<&str>, limit: usize) -> Result<Vec<EmergencyIncident>> {
        let limit = limit.clamp(1, 1_000);
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::page(
                &lock(conn, "sqlite history connection"),
                state,
                limit,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_page(state, limit),
        }
    }

    pub fn emergency_active_stats(&self, now: f64) -> Result<(usize, f64)> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => super::sqlite::emergency::active_stats(
                &lock(conn, "sqlite history connection"),
                now,
            ),
            HistoryBackend::Postgres(worker) => worker.emergency_stats(now),
        }
    }

    pub(super) fn export_emergencies(&self) -> Result<Vec<EmergencyIncident>> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                super::sqlite::emergency::export_all(&lock(conn, "sqlite history connection"))
            }
            HistoryBackend::Postgres(worker) => worker.emergency_export(),
        }
    }

    pub(super) fn import_emergency(&self, incident: &EmergencyIncident) -> Result<()> {
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                super::sqlite::emergency::import(&lock(conn, "sqlite history connection"), incident)
            }
            HistoryBackend::Postgres(worker) => worker.emergency_import(incident),
        }
    }
}
