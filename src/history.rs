use crate::config::HistoryConfig;
use anyhow::{Context, Result, anyhow, bail};
use postgres::{Client, NoTls};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;

const SCHEMA_VERSION: i64 = 1;
const DEFAULT_MIGRATION_BATCH: usize = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryEntry {
    pub ts: f64,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub channel: String,
    pub suppressed_by: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliveryPage {
    pub entries: Vec<DeliveryEntry>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

pub struct HistoryStore {
    backend: HistoryBackend,
    retention: usize,
}

enum HistoryBackend {
    Sqlite(Mutex<Connection>),
    Postgres(PostgresWorker),
}

struct PostgresWorker {
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
        let limit = limit.clamp(1, 10_000);
        let offset = offset.min(1_000_000);
        match &self.backend {
            HistoryBackend::Sqlite(conn) => {
                let conn = lock(conn, "sqlite history connection");
                let total = sqlite_count(&conn)?;
                let entries = sqlite_page(&conn, limit, offset)?;
                Ok(DeliveryPage {
                    entries,
                    total,
                    limit,
                    offset,
                })
            }
            HistoryBackend::Postgres(worker) => worker.deliveries_page(limit, offset),
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
}

impl PostgresWorker {
    fn start(url: String, retention: usize, create_schema: bool) -> Result<Self> {
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

    fn record_delivery(&self, entry: &DeliveryEntry) -> Result<()> {
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

    fn deliveries_page(&self, limit: usize, offset: usize) -> Result<DeliveryPage> {
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

    fn export_all(&self) -> Result<Vec<DeliveryEntry>> {
        let (reply, result) = mpsc::channel();
        self.tx
            .send(PostgresCommand::ExportAll { reply })
            .context("send postgres history export request")?;
        result
            .recv()
            .context("receive postgres history export response")?
    }
}

pub fn migrate_between(src: &HistoryConfig, dst: &HistoryConfig) -> Result<usize> {
    let src = HistoryStore::open_existing(src).context("open source history store")?;
    let dst = HistoryStore::open(dst).context("open destination history store")?;
    let rows = src.export_all()?;
    let mut copied = 0;
    for chunk in rows.chunks(DEFAULT_MIGRATION_BATCH) {
        for row in chunk {
            dst.record_delivery(row)?;
            copied += 1;
        }
    }
    Ok(copied)
}

pub fn run_migrate_cli(args: &[String]) -> Result<()> {
    let src_backend = arg_value(args, "--from")
        .or_else(|| arg_value(args, "--source"))
        .ok_or_else(|| anyhow!("missing --from sqlite|postgres"))?;
    let src_url = arg_value(args, "--from-url")
        .or_else(|| arg_value(args, "--source-url"))
        .ok_or_else(|| anyhow!("missing --from-url"))?;
    let dst_backend = arg_value(args, "--to")
        .or_else(|| arg_value(args, "--dest"))
        .ok_or_else(|| anyhow!("missing --to sqlite|postgres"))?;
    let dst_url = arg_value(args, "--to-url")
        .or_else(|| arg_value(args, "--dest-url"))
        .ok_or_else(|| anyhow!("missing --to-url"))?;
    let retention = arg_value(args, "--retention")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let src = config_from_spec(&src_backend, &src_url, retention)?;
    let dst = config_from_spec(&dst_backend, &dst_url, retention)?;
    let copied = migrate_between(&src, &dst)?;
    println!("migrated {copied} delivery history rows");
    Ok(())
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].clone())
}

fn config_from_spec(backend: &str, url: &str, retention: usize) -> Result<HistoryConfig> {
    match backend {
        "sqlite" => Ok(HistoryConfig {
            backend: "sqlite".to_string(),
            sqlite_path: PathBuf::from(url),
            postgres_url: String::new(),
            retention,
            default_limit: 500,
        }),
        "postgres" | "postgresql" => Ok(HistoryConfig {
            backend: "postgres".to_string(),
            sqlite_path: PathBuf::from("/tmp/klaxond-unused.db"),
            postgres_url: url.to_string(),
            retention,
            default_limit: 500,
        }),
        other => bail!("unsupported migration backend {other:?}"),
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

fn open_sqlite(path: &Path, create_schema: bool) -> Result<Connection> {
    let flags = if create_schema {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        if !path.exists() {
            bail!("source sqlite history {} does not exist", path.display());
        }
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags)
        .with_context(|| format!("open sqlite history {}", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    if create_schema {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
    }
    Ok(conn)
}

fn validate_sqlite_schema(conn: &Connection) -> Result<()> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'klaxond_deliveries'",
        [],
        |row| row.get(0),
    )?;
    if count == 0 {
        bail!("source sqlite history does not contain klaxond_deliveries");
    }
    Ok(())
}

fn validate_postgres_schema(client: &mut Client) -> Result<()> {
    let row = client.query_one("SELECT to_regclass('klaxond_deliveries')::text", &[])?;
    let table: Option<String> = row.get(0);
    if table.is_none() {
        bail!("source postgres history does not contain klaxond_deliveries");
    }
    Ok(())
}

fn migrate_sqlite(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS klaxond_schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS klaxond_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
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
    conn.execute(
        "INSERT OR IGNORE INTO klaxond_schema_migrations(version) VALUES (?1)",
        params![SCHEMA_VERSION],
    )?;
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

fn sqlite_insert(conn: &Connection, entry: &DeliveryEntry) -> Result<()> {
    let hash = dedupe_hash(entry);
    conn.execute(
        r#"
INSERT OR IGNORE INTO klaxond_deliveries
  (ts, source, severity, title, channel, suppressed_by, dedupe_hash)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
"#,
        params![
            entry.ts,
            &entry.source,
            &entry.severity,
            &entry.title,
            &entry.channel,
            &entry.suppressed_by,
            hash,
        ],
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

fn sqlite_count(conn: &Connection) -> Result<usize> {
    Ok(
        conn.query_row("SELECT COUNT(*) FROM klaxond_deliveries", [], |row| {
            row.get::<_, i64>(0)
        })? as usize,
    )
}

fn postgres_count(client: &mut Client) -> Result<usize> {
    let row = client.query_one("SELECT COUNT(*) FROM klaxond_deliveries", &[])?;
    Ok(row.get::<_, i64>(0) as usize)
}

fn sqlite_page(conn: &Connection, limit: usize, offset: usize) -> Result<Vec<DeliveryEntry>> {
    let mut stmt = conn.prepare(
        r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2
"#,
    )?;
    let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
        Ok(DeliveryEntry {
            ts: row.get(0)?,
            source: row.get(1)?,
            severity: row.get(2)?,
            title: row.get(3)?,
            channel: row.get(4)?,
            suppressed_by: row.get(5)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn sqlite_export_all(conn: &mut Connection) -> Result<Vec<DeliveryEntry>> {
    let tx = conn.unchecked_transaction()?;
    let rows = {
        let mut stmt = tx.prepare(
            r#"
SELECT ts, source, severity, title, channel, suppressed_by
FROM klaxond_deliveries
ORDER BY ts ASC, id ASC
"#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeliveryEntry {
                ts: row.get(0)?,
                source: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                channel: row.get(4)?,
                suppressed_by: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tx.commit()?;
    Ok(rows)
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

fn sqlite_prune(conn: &Connection, retention: usize) -> Result<()> {
    if retention == 0 {
        return Ok(());
    }
    conn.execute(
        r#"
DELETE FROM klaxond_deliveries
WHERE id NOT IN (
  SELECT id FROM klaxond_deliveries ORDER BY ts DESC, id DESC LIMIT ?1
)
"#,
        params![retention as i64],
    )?;
    Ok(())
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

fn dedupe_hash(entry: &DeliveryEntry) -> String {
    let mut h = Sha256::new();
    h.update(entry.ts.to_bits().to_be_bytes());
    h.update(b"\0");
    h.update(entry.source.as_bytes());
    h.update(b"\0");
    h.update(entry.severity.as_bytes());
    h.update(b"\0");
    h.update(entry.title.as_bytes());
    h.update(b"\0");
    h.update(entry.channel.as_bytes());
    h.update(b"\0");
    h.update(entry.suppressed_by.as_bytes());
    hex::encode(h.finalize())
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        tracing::error!("recovering poisoned mutex: {name}");
        poisoned.into_inner()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sqlite_cfg(path: PathBuf, retention: usize) -> HistoryConfig {
        HistoryConfig {
            backend: "sqlite".to_string(),
            sqlite_path: path,
            postgres_url: String::new(),
            retention,
            default_limit: 500,
        }
    }

    fn entry(i: usize) -> DeliveryEntry {
        DeliveryEntry {
            ts: 1000.0 + i as f64,
            source: "grafana".to_string(),
            severity: "warning".to_string(),
            title: format!("Alert {i}"),
            channel: "ntfy".to_string(),
            suppressed_by: String::new(),
        }
    }

    #[test]
    fn sqlite_history_paginates_and_prunes_by_retention() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 3)).unwrap();
        for i in 0..5 {
            store.record_delivery(&entry(i)).unwrap();
        }

        let page = store.deliveries_page(2, 0).unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].title, "Alert 4");
        assert_eq!(page.entries[1].title, "Alert 3");

        let second = store.deliveries_page(2, 2).unwrap();
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].title, "Alert 2");
    }

    #[test]
    fn sqlite_history_migration_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let src = sqlite_cfg(tmp.path().join("src.db"), 0);
        let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
        let src_store = HistoryStore::open(&src).unwrap();
        src_store.record_delivery(&entry(1)).unwrap();
        src_store.record_delivery(&entry(2)).unwrap();

        assert_eq!(migrate_between(&src, &dst).unwrap(), 2);
        assert_eq!(migrate_between(&src, &dst).unwrap(), 2);

        let dst_store = HistoryStore::open(&dst).unwrap();
        let page = dst_store.deliveries_page(10, 0).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.entries[0].title, "Alert 2");
    }

    #[test]
    fn sqlite_history_migration_requires_existing_source() {
        let tmp = TempDir::new().unwrap();
        let src = sqlite_cfg(tmp.path().join("missing.db"), 0);
        let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
        let err = migrate_between(&src, &dst).unwrap_err().to_string();
        assert!(err.contains("open source history store"));
        assert!(!src.sqlite_path.exists());
    }
}
