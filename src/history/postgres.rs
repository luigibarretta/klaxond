use super::{DeliveryEntry, DeliveryPage, SCHEMA_VERSION, dedupe_hash};
use anyhow::{Context, Result, bail};
use postgres::{Client, NoTls};
use std::sync::mpsc;
use std::thread;

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
}

fn connect_postgres(url: &str, create_schema: bool) -> Result<Client> {
    let mut client =
        Client::connect(url, NoTls).with_context(|| "connect postgres history database")?;
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

fn validate_postgres_schema(client: &mut Client) -> Result<()> {
    let row = client.query_one("SELECT to_regclass('klaxond_deliveries')::text", &[])?;
    let table: Option<String> = row.get(0);
    if table.is_none() {
        bail!("source postgres history does not contain klaxond_deliveries");
    }
    Ok(())
}

fn migrate_postgres(client: &mut Client) -> Result<()> {
    client.batch_execute(
        r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version BIGINT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS klaxond_deliveries (
  id BIGSERIAL PRIMARY KEY,
  ts DOUBLE PRECISION NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  channel TEXT NOT NULL,
  suppressed_by TEXT NOT NULL DEFAULT '',
  dedupe_hash TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_klaxond_deliveries_dedupe_hash ON klaxond_deliveries(dedupe_hash);
CREATE INDEX IF NOT EXISTS idx_klaxond_deliveries_ts_id_desc ON klaxond_deliveries(ts DESC, id DESC);
"#,
    )?;
    client.execute(
        "INSERT INTO klaxond_schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&SCHEMA_VERSION],
    )?;
    Ok(())
}

fn postgres_insert(client: &mut Client, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    client.execute(
        r#"
INSERT INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, dedupe_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (dedupe_hash) DO NOTHING
"#,
        &[
            &entry.ts,
            &entry.source,
            &entry.severity,
            &entry.title,
            &entry.channel,
            &entry.suppressed_by,
            &hash,
        ],
    )?;
    Ok(())
}

fn postgres_count(client: &mut Client) -> Result<usize> {
    let row = client.query_one("SELECT COUNT(*) FROM klaxond_deliveries", &[])?;
    Ok(row.get::<_, i64>(0) as usize)
}

fn postgres_page(client: &mut Client, limit: usize, offset: usize) -> Result<Vec<DeliveryEntry>> {
    let rows = client.query(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts DESC, id DESC
LIMIT $1 OFFSET $2
"#,
        &[&(limit as i64), &(offset as i64)],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
        })
        .collect())
}

fn postgres_export_all(client: &mut Client) -> Result<Vec<DeliveryEntry>> {
    let mut tx = client.transaction()?;
    let rows = tx.query(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts ASC, id ASC
"#,
        &[],
    )?;
    let entries = rows
        .into_iter()
        .map(|row| DeliveryEntry {
            ts: row.get(0),
            source: row.get(1),
            severity: row.get(2),
            title: row.get(3),
            channel: row.get(4),
            suppressed_by: row.get(5),
        })
        .collect();
    tx.commit()?;
    Ok(entries)
}

fn postgres_prune(client: &mut Client, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    client.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT $1
)
"#,
        &[&(retention as i64)],
    )?;
    Ok(())
}
