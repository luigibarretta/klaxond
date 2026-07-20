use super::RuntimeAuthState;
use super::{DeliveryEntry, DeliveryPage, RepeatCandidate, RepeatDecision, RepeatState};
use anyhow::{Context, Result, bail};
use postgres::{Client, NoTls};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod auth_state;
mod rate_limit;
mod repeat;
mod session;
mod session_locks;
mod storage;
mod worker_rate_limit;
mod worker_repeat;
mod worker_session;

use self::storage::{
    count as postgres_count, export_all as postgres_export_all, insert as postgres_insert,
    migrate as migrate_postgres, page as postgres_page, prune as postgres_prune,
    validate_schema as validate_postgres_schema,
};

pub(super) struct PostgresWorker {
    tx: mpsc::Sender<PostgresCommand>,
}

enum PostgresCommand {
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
    Session(worker_session::SessionCommand),
    RateLimit(worker_rate_limit::RateLimitCommand),
}

impl PostgresWorker {
    pub(super) fn start(url: String, retention: usize, create_schema: bool) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<PostgresCommand>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let worker_url = url.clone();
        thread::Builder::new()
            .name("klaxond-history-postgres".to_string())
            .spawn(move || {
                let mut client = match connect_postgres(&worker_url, create_schema) {
                    Ok(client) => {
                        let _ = ready_tx.send(Ok(()));
                        client
                    }
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                for command in rx {
                    match command {
                        PostgresCommand::Record { entry, reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| {
                                    postgres_insert(client, &entry)?;
                                    postgres_prune(client, retention)
                                },
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::Page {
                            limit,
                            offset,
                            reply,
                        } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| {
                                    let total = postgres_count(client)?;
                                    let entries = postgres_page(client, limit, offset)?;
                                    Ok(DeliveryPage {
                                        entries,
                                        total,
                                        limit,
                                        offset,
                                    })
                                },
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::ExportAll { reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                postgres_export_all,
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::ReserveRepeat { candidate, reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| repeat::reserve(client, &candidate),
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::CompleteRepeat {
                            fingerprint,
                            reservation_token,
                            delivered_at,
                            reply,
                        } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| {
                                    repeat::complete(
                                        client,
                                        &fingerprint,
                                        &reservation_token,
                                        delivered_at,
                                    )
                                },
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::RecentRepeatSuppressions { limit, reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| repeat::recent_suppressions(client, limit),
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::ExportRepeatStates { reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                repeat::export_all,
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::ImportRepeatState { state, reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| repeat::import(client, &state),
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::ImportAuthState { state, reply } => {
                            let result = postgres_with_retry(
                                &worker_url,
                                create_schema,
                                &mut client,
                                |client| auth_state::import(client, &state),
                            );
                            let _ = reply.send(result);
                        }
                        PostgresCommand::Session(command) => worker_session::execute(
                            command,
                            &worker_url,
                            create_schema,
                            &mut client,
                        ),
                        PostgresCommand::RateLimit(command) => worker_rate_limit::execute(
                            command,
                            &worker_url,
                            create_schema,
                            &mut client,
                        ),
                    }
                }
            })
            .context("spawn postgres history worker")?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { tx }),
            Ok(Err(err)) => Err(err),
            Err(err) => bail!("postgres history worker failed to start: {err}"),
        }
    }

    pub(super) fn record_delivery(&self, entry: &DeliveryEntry) -> Result<()> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::Record {
                entry: entry.clone(),
                reply,
            })
            .context("send postgres history record request")?;
        result
            .recv()
            .context("receive postgres history record response")?
    }

    pub(super) fn deliveries_page(&self, limit: usize, offset: usize) -> Result<DeliveryPage> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::Page {
                limit,
                offset,
                reply,
            })
            .context("send postgres history page request")?;
        result
            .recv()
            .context("receive postgres history page response")?
    }

    pub(super) fn export_all(&self) -> Result<Vec<DeliveryEntry>> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::ExportAll { reply })
            .context("send postgres history export request")?;
        result
            .recv()
            .context("receive postgres history export response")?
    }

    pub(super) fn import_runtime_auth_state(&self, state: &RuntimeAuthState) -> Result<()> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::ImportAuthState {
                state: state.clone(),
                reply,
            })
            .context("send postgres auth state import request")?;
        result
            .recv()
            .context("receive postgres auth state import response")?
    }
}

fn connect_postgres(url: &str, create_schema: bool) -> Result<Client> {
    let mut config = url
        .parse::<postgres::Config>()
        .with_context(|| "parse postgres history database URL")?;
    config.connect_timeout(Duration::from_secs(5));
    let mut client = config
        .connect(NoTls)
        .with_context(|| "connect postgres history database")?;
    client.batch_execute("SET statement_timeout = '10s'; SET lock_timeout = '5s';")?;
    if create_schema {
        migrate_postgres(&mut client)?;
    } else {
        validate_postgres_schema(&mut client)?;
    }
    Ok(client)
}

fn postgres_with_retry<T>(
    url: &str,
    create_schema: bool,
    client: &mut Client,
    f: impl Fn(&mut Client) -> Result<T>,
) -> Result<T> {
    match f(client) {
        Ok(value) => Ok(value),
        Err(first_err) => {
            tracing::warn!("postgres history operation failed, reconnecting: {first_err}");
            *client = connect_postgres(url, create_schema)
                .context("reconnect postgres history database")?;
            f(client).with_context(|| format!("postgres history retry after: {first_err}"))
        }
    }
}
