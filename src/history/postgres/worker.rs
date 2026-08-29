use super::storage;
use super::{
    DeliveryEntry, DeliveryPage, RepeatCandidate, RepeatDecision, RepeatState, RuntimeAuthState,
    auth_state, connect_postgres, emergency, postgres_with_retry, repeat, worker_rate_limit,
    worker_session,
};
use crate::history::{
    EmergencyAttempt, EmergencyCandidate, EmergencyIncident, EmergencyRegistration,
};
use anyhow::{Context, Result, bail};
use postgres::Client;
use std::sync::mpsc;
use std::thread;

pub(super) enum PostgresCommand {
    Record {
        entry: DeliveryEntry,
        reply: mpsc::Sender<Result<()>>,
    },
    Page {
        limit: usize,
        offset: usize,
        reply: mpsc::Sender<Result<DeliveryPage>>,
    },
    ExportAll {
        reply: mpsc::Sender<Result<Vec<DeliveryEntry>>>,
    },
    ReserveRepeat {
        candidate: RepeatCandidate,
        reply: mpsc::Sender<Result<RepeatDecision>>,
    },
    CompleteRepeat {
        fingerprint: String,
        reservation_token: String,
        delivered_at: Option<f64>,
        reply: mpsc::Sender<Result<()>>,
    },
    RecentRepeatSuppressions {
        limit: usize,
        reply: mpsc::Sender<Result<Vec<RepeatState>>>,
    },
    ExportRepeatStates {
        reply: mpsc::Sender<Result<Vec<RepeatState>>>,
    },
    ImportRepeatState {
        state: RepeatState,
        reply: mpsc::Sender<Result<()>>,
    },
    ImportAuthState {
        state: RuntimeAuthState,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyRegister {
        candidate: EmergencyCandidate,
        reply: mpsc::Sender<Result<EmergencyRegistration>>,
    },
    EmergencyInitialAttempt {
        attempt: EmergencyAttempt,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyReserve {
        now: f64,
        lease_until: f64,
        token: String,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyComplete {
        attempt: EmergencyAttempt,
        reply: mpsc::Sender<Result<bool>>,
    },
    EmergencyTerminalize {
        receipt: String,
        state: String,
        actor: String,
        now: f64,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyTerminalizeFingerprint {
        fingerprint: String,
        state: String,
        actor: String,
        now: f64,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyExpire {
        now: f64,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyRetry {
        receipt: String,
        now: f64,
        reply: mpsc::Sender<Result<bool>>,
    },
    EmergencyGet {
        receipt: String,
        reply: mpsc::Sender<Result<Option<EmergencyIncident>>>,
    },
    EmergencyPage {
        state: Option<String>,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyExport {
        reply: mpsc::Sender<Result<Vec<EmergencyIncident>>>,
    },
    EmergencyImport {
        incident: EmergencyIncident,
        reply: mpsc::Sender<Result<()>>,
    },
    EmergencyStats {
        now: f64,
        reply: mpsc::Sender<Result<(usize, f64)>>,
    },
    Session(worker_session::SessionCommand),
    RateLimit(worker_rate_limit::RateLimitCommand),
}

struct WorkerContext {
    url: String,
    retention: usize,
    create_schema: bool,
    client: Client,
}

impl WorkerContext {
    fn execute(&mut self, command: PostgresCommand) {
        match command {
            PostgresCommand::Record { entry, reply } => self.record(entry, reply),
            PostgresCommand::Page {
                limit,
                offset,
                reply,
            } => self.page(limit, offset, reply),
            PostgresCommand::ExportAll { reply } => self.export_all(reply),
            PostgresCommand::ReserveRepeat { candidate, reply } => {
                self.reserve_repeat(candidate, reply);
            }
            PostgresCommand::CompleteRepeat {
                fingerprint,
                reservation_token,
                delivered_at,
                reply,
            } => self.complete_repeat(fingerprint, reservation_token, delivered_at, reply),
            PostgresCommand::RecentRepeatSuppressions { limit, reply } => {
                self.recent_suppressions(limit, reply);
            }
            PostgresCommand::ExportRepeatStates { reply } => self.export_repeat_states(reply),
            PostgresCommand::ImportRepeatState { state, reply } => {
                self.import_repeat_state(state, reply);
            }
            PostgresCommand::ImportAuthState { state, reply } => {
                self.import_auth_state(state, reply);
            }
            PostgresCommand::EmergencyRegister { candidate, reply } => {
                let r = self.with_retry(|c| emergency::register(c, &candidate));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyInitialAttempt { attempt, reply } => {
                let r = self.with_retry(|c| emergency::record_initial_attempt(c, &attempt));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyReserve {
                now,
                lease_until,
                token,
                reply,
            } => {
                let r = self.with_retry(|c| emergency::reserve_due(c, now, lease_until, &token));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyComplete { attempt, reply } => {
                let r = self.with_retry(|c| emergency::complete_attempt(c, &attempt));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyTerminalize {
                receipt,
                state,
                actor,
                now,
                reply,
            } => {
                let r =
                    self.with_retry(|c| emergency::terminalize(c, &receipt, &state, &actor, now));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyTerminalizeFingerprint {
                fingerprint,
                state,
                actor,
                now,
                reply,
            } => {
                let r = self.with_retry(|c| {
                    emergency::terminalize_fingerprint(c, &fingerprint, &state, &actor, now)
                });
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyExpire { now, limit, reply } => {
                let r = self.with_retry(|c| emergency::expire_due(c, now, limit));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyRetry {
                receipt,
                now,
                reply,
            } => {
                let r = self.with_retry(|c| emergency::retry_now(c, &receipt, now));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyGet { receipt, reply } => {
                let r = self.with_retry(|c| emergency::get(c, &receipt));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyPage {
                state,
                limit,
                reply,
            } => {
                let r = self.with_retry(|c| emergency::page(c, state.as_deref(), limit));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyExport { reply } => {
                let r = self.with_retry(emergency::export_all);
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyImport { incident, reply } => {
                let r = self.with_retry(|c| emergency::import(c, &incident));
                let _ = reply.send(r);
            }
            PostgresCommand::EmergencyStats { now, reply } => {
                let r = self.with_retry(|c| emergency::active_stats(c, now));
                let _ = reply.send(r);
            }
            PostgresCommand::Session(command) => {
                worker_session::execute(command, &self.url, self.create_schema, &mut self.client)
            }
            PostgresCommand::RateLimit(command) => {
                worker_rate_limit::execute(command, &self.url, self.create_schema, &mut self.client)
            }
        }
    }

    fn record(&mut self, entry: DeliveryEntry, reply: mpsc::Sender<Result<()>>) {
        let retention = self.retention;
        let result = self.with_retry(|client| {
            storage::insert(client, &entry)?;
            storage::prune(client, retention)
        });
        let _ = reply.send(result);
    }

    fn page(&mut self, limit: usize, offset: usize, reply: mpsc::Sender<Result<DeliveryPage>>) {
        let result = self.with_retry(|client| {
            let total = storage::count(client)?;
            let entries = storage::page(client, limit, offset)?;
            Ok(DeliveryPage {
                entries,
                total,
                limit,
                offset,
            })
        });
        let _ = reply.send(result);
    }

    fn export_all(&mut self, reply: mpsc::Sender<Result<Vec<DeliveryEntry>>>) {
        let result = self.with_retry(storage::export_all);
        let _ = reply.send(result);
    }

    fn reserve_repeat(
        &mut self,
        candidate: RepeatCandidate,
        reply: mpsc::Sender<Result<RepeatDecision>>,
    ) {
        let result = self.with_retry(|client| repeat::reserve(client, &candidate));
        let _ = reply.send(result);
    }

    fn complete_repeat(
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

    fn recent_suppressions(&mut self, limit: usize, reply: mpsc::Sender<Result<Vec<RepeatState>>>) {
        let result = self.with_retry(|client| repeat::recent_suppressions(client, limit));
        let _ = reply.send(result);
    }

    fn export_repeat_states(&mut self, reply: mpsc::Sender<Result<Vec<RepeatState>>>) {
        let result = self.with_retry(repeat::export_all);
        let _ = reply.send(result);
    }

    fn import_repeat_state(&mut self, state: RepeatState, reply: mpsc::Sender<Result<()>>) {
        let result = self.with_retry(|client| repeat::import(client, &state));
        let _ = reply.send(result);
    }

    fn import_auth_state(&mut self, state: RuntimeAuthState, reply: mpsc::Sender<Result<()>>) {
        let result = self.with_retry(|client| auth_state::import(client, &state));
        let _ = reply.send(result);
    }

    fn with_retry<T>(&mut self, operation: impl Fn(&mut Client) -> Result<T>) -> Result<T> {
        postgres_with_retry(&self.url, self.create_schema, &mut self.client, operation)
    }
}

pub(super) fn spawn(
    url: String,
    retention: usize,
    create_schema: bool,
) -> Result<mpsc::Sender<PostgresCommand>> {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::Builder::new()
        .name("klaxond-history-postgres".to_string())
        .spawn(move || run(url, retention, create_schema, rx, ready_tx))
        .context("spawn postgres history worker")?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(tx),
        Ok(Err(err)) => Err(err),
        Err(err) => bail!("postgres history worker failed to start: {err}"),
    }
}

fn run(
    url: String,
    retention: usize,
    create_schema: bool,
    commands: mpsc::Receiver<PostgresCommand>,
    ready: mpsc::Sender<Result<()>>,
) {
    let client = match connect_postgres(&url, create_schema) {
        Ok(client) => client,
        Err(err) => {
            let _ = ready.send(Err(err));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    let mut context = WorkerContext {
        url,
        retention,
        create_schema,
        client,
    };
    for command in commands {
        context.execute(command);
    }
}
