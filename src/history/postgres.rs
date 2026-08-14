use super::RuntimeAuthState;
use super::{DeliveryEntry, DeliveryPage, RepeatCandidate, RepeatDecision, RepeatState};
use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use std::sync::mpsc;
use std::time::Duration;

mod auth_state;
mod rate_limit;
mod repeat;
mod session;
mod session_locks;
mod storage;
mod worker;
mod worker_rate_limit;
mod worker_repeat;
mod worker_session;

use self::storage::{migrate as migrate_postgres, validate_schema as validate_postgres_schema};
use self::worker::PostgresCommand;

pub(super) struct PostgresWorker {
    tx: mpsc::Sender<PostgresCommand>,
}

impl PostgresWorker {
    pub(super) fn start(url: String, retention: usize, create_schema: bool) -> Result<Self> {
        Ok(Self {
            tx: worker::spawn(url, retention, create_schema)?,
        })
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
