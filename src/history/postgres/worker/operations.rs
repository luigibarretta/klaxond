use super::WorkerContext;
use crate::history::postgres::{auth_state, delivery, postgres_with_retry, repeat};
use crate::history::{
    DeliveryActivity, DeliveryEntry, DeliveryPage, DeliveryQuery, RepeatCandidate, RepeatDecision,
    RepeatState, RuntimeAuthState,
};
use anyhow::Result;
use postgres::Client;
use std::sync::mpsc;

impl WorkerContext {
    pub(super) fn record(&mut self, entry: DeliveryEntry, reply: mpsc::Sender<Result<()>>) {
        let retention = self.retention;
        let result = self.with_retry(|client| {
            delivery::insert(client, &entry)?;
            delivery::prune(client, retention)
        });
        let _ = reply.send(result);
    }

    pub(super) fn page(&mut self, query: DeliveryQuery, reply: mpsc::Sender<Result<DeliveryPage>>) {
        let result = self.with_retry(|client| {
            let total = delivery::count(client, &query)?;
            let entries = delivery::page(client, &query)?;
            Ok(DeliveryPage {
                entries,
                total,
                limit: query.limit,
                offset: query.offset,
            })
        });
        let _ = reply.send(result);
    }

    pub(super) fn activity(
        &mut self,
        hours: u16,
        since: f64,
        until: f64,
        reply: mpsc::Sender<Result<DeliveryActivity>>,
    ) {
        let result = self.with_retry(|client| delivery::activity(client, hours, since, until));
        let _ = reply.send(result);
    }

    pub(super) fn export_all(&mut self, reply: mpsc::Sender<Result<Vec<DeliveryEntry>>>) {
        let result = self.with_retry(delivery::export_all);
        let _ = reply.send(result);
    }

    pub(super) fn reserve_repeat(
        &mut self,
        candidate: RepeatCandidate,
        reply: mpsc::Sender<Result<RepeatDecision>>,
    ) {
        let result = self.with_retry(|client| repeat::reserve(client, &candidate));
        let _ = reply.send(result);
    }

    pub(super) fn complete_repeat(
        &mut self,
        fingerprint: String,
        reservation_token: String,
        delivered_at: Option<f64>,
        reply: mpsc::Sender<Result<()>>,
    ) {
        let result = self.with_retry(|client| {
            repeat::complete(client, &fingerprint, &reservation_token, delivered_at)
        });
        let _ = reply.send(result);
    }

    pub(super) fn recent_suppressions(
        &mut self,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<RepeatState>>>,
    ) {
        let result = self.with_retry(|client| repeat::recent_suppressions(client, limit));
        let _ = reply.send(result);
    }

    pub(super) fn export_repeat_states(&mut self, reply: mpsc::Sender<Result<Vec<RepeatState>>>) {
        let result = self.with_retry(repeat::export_all);
        let _ = reply.send(result);
    }

    pub(super) fn import_repeat_state(
        &mut self,
        state: RepeatState,
        reply: mpsc::Sender<Result<()>>,
    ) {
        let result = self.with_retry(|client| repeat::import(client, &state));
        let _ = reply.send(result);
    }

    pub(super) fn import_auth_state(
        &mut self,
        state: RuntimeAuthState,
        reply: mpsc::Sender<Result<()>>,
    ) {
        let result = self.with_retry(|client| auth_state::import(client, &state));
        let _ = reply.send(result);
    }

    pub(super) fn with_retry<T>(
        &mut self,
        operation: impl Fn(&mut Client) -> Result<T>,
    ) -> Result<T> {
        postgres_with_retry(&self.url, self.create_schema, &mut self.client, operation)
    }
}
