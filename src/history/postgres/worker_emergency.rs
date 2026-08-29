use super::{PostgresCommand, PostgresWorker};
use crate::history::{
    EmergencyAttempt, EmergencyCandidate, EmergencyIncident, EmergencyRegistration,
};
use anyhow::{Context, Result};
use std::sync::mpsc;

impl PostgresWorker {
    fn emergency_request<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<T>>) -> PostgresCommand,
        operation: &str,
    ) -> Result<T> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(command(reply))
            .with_context(|| format!("send postgres {operation} request"))?;
        result
            .recv()
            .with_context(|| format!("receive postgres {operation} response"))?
    }

    pub(in crate::history) fn emergency_register(
        &self,
        candidate: &EmergencyCandidate,
    ) -> Result<EmergencyRegistration> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyRegister {
                candidate: candidate.clone(),
                reply,
            },
            "emergency register",
        )
    }
    pub(in crate::history) fn emergency_initial_attempt(
        &self,
        attempt: &EmergencyAttempt,
    ) -> Result<()> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyInitialAttempt {
                attempt: attempt.clone(),
                reply,
            },
            "emergency initial attempt",
        )
    }
    pub(in crate::history) fn emergency_reserve(
        &self,
        now: f64,
        lease_until: f64,
        token: &str,
    ) -> Result<Option<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyReserve {
                now,
                lease_until,
                token: token.into(),
                reply,
            },
            "emergency reserve",
        )
    }
    pub(in crate::history) fn emergency_complete(
        &self,
        attempt: &EmergencyAttempt,
    ) -> Result<bool> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyComplete {
                attempt: attempt.clone(),
                reply,
            },
            "emergency complete",
        )
    }
    pub(in crate::history) fn emergency_terminalize(
        &self,
        receipt: &str,
        state: &str,
        actor: &str,
        now: f64,
    ) -> Result<Option<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyTerminalize {
                receipt: receipt.into(),
                state: state.into(),
                actor: actor.into(),
                now,
                reply,
            },
            "emergency terminalize",
        )
    }
    pub(in crate::history) fn emergency_terminalize_fingerprint(
        &self,
        fingerprint: &str,
        state: &str,
        actor: &str,
        now: f64,
    ) -> Result<Option<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyTerminalizeFingerprint {
                fingerprint: fingerprint.into(),
                state: state.into(),
                actor: actor.into(),
                now,
                reply,
            },
            "emergency resolve",
        )
    }
    pub(in crate::history) fn emergency_expire(
        &self,
        now: f64,
        limit: usize,
    ) -> Result<Vec<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyExpire { now, limit, reply },
            "emergency expire",
        )
    }
    pub(in crate::history) fn emergency_retry(&self, receipt: &str, now: f64) -> Result<bool> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyRetry {
                receipt: receipt.into(),
                now,
                reply,
            },
            "emergency retry",
        )
    }
    pub(in crate::history) fn emergency_get(
        &self,
        receipt: &str,
    ) -> Result<Option<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyGet {
                receipt: receipt.into(),
                reply,
            },
            "emergency get",
        )
    }
    pub(in crate::history) fn emergency_page(
        &self,
        state: Option<&str>,
        limit: usize,
    ) -> Result<Vec<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyPage {
                state: state.map(str::to_string),
                limit,
                reply,
            },
            "emergency page",
        )
    }
    pub(in crate::history) fn emergency_export(&self) -> Result<Vec<EmergencyIncident>> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyExport { reply },
            "emergency export",
        )
    }
    pub(in crate::history) fn emergency_import(&self, incident: &EmergencyIncident) -> Result<()> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyImport {
                incident: incident.clone(),
                reply,
            },
            "emergency import",
        )
    }
    pub(in crate::history) fn emergency_stats(&self, now: f64) -> Result<(usize, f64)> {
        self.emergency_request(
            |reply| PostgresCommand::EmergencyStats { now, reply },
            "emergency stats",
        )
    }
}
