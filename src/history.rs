use crate::config::HistoryConfig;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

mod postgres;
mod sqlite;
#[cfg(test)]
mod tests;

use postgres::PostgresWorker;
use sqlite::{
    SqliteConnection, migrate_sqlite, open_sqlite, sqlite_count, sqlite_export_all, sqlite_insert,
    sqlite_page, sqlite_prune, validate_sqlite_schema,
};

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
