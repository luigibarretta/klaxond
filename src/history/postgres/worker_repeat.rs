use super::{PostgresCommand, PostgresWorker};
use crate::history::{RepeatCandidate, RepeatDecision, RepeatState};
use anyhow::{Context, Result};
use std::sync::mpsc;

impl PostgresWorker {
    pub(in crate::history) fn reserve_repeat(
        &self,
        candidate: &RepeatCandidate,
    ) -> Result<RepeatDecision> {
        self.repeat_request(
            |reply| PostgresCommand::ReserveRepeat {
                candidate: candidate.clone(),
                reply,
            },
            "repeat reservation",
        )
    }

    pub(in crate::history) fn complete_repeat(
        &self,
        fingerprint: &str,
        reservation_token: &str,
        delivered_at: Option<f64>,
    ) -> Result<()> {
        self.repeat_request(
            |reply| PostgresCommand::CompleteRepeat {
                fingerprint: fingerprint.to_string(),
                reservation_token: reservation_token.to_string(),
                delivered_at,
                reply,
            },
            "repeat completion",
        )
    }

    pub(in crate::history) fn recent_repeat_suppressions(
        &self,
        limit: usize,
    ) -> Result<Vec<RepeatState>> {
        self.repeat_request(
            |reply| PostgresCommand::RecentRepeatSuppressions { limit, reply },
            "recent repeat suppressions",
        )
    }

    pub(in crate::history) fn export_repeat_states(&self) -> Result<Vec<RepeatState>> {
        self.repeat_request(
            |reply| PostgresCommand::ExportRepeatStates { reply },
            "repeat state export",
        )
    }

    pub(in crate::history) fn import_repeat_state(&self, state: &RepeatState) -> Result<()> {
        self.repeat_request(
            |reply| PostgresCommand::ImportRepeatState {
                state: state.clone(),
                reply,
            },
            "repeat state import",
        )
    }

    fn repeat_request<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<T>>) -> PostgresCommand,
        operation: &str,
    ) -> Result<T> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(command(reply))
            .with_context(|| format!("send postgres history {operation} request"))?;
        result
            .recv()
            .with_context(|| format!("receive postgres history {operation} response"))?
    }
}
