use super::{HistoryStore, RuntimeAuthState};
use crate::config::HistoryConfig;
use anyhow::{Context, Result, anyhow, bail};
use std::path::PathBuf;

const DEFAULT_MIGRATION_BATCH: usize = 500;

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
    for state in src.export_repeat_states()? {
        dst.import_repeat_state(&state)?;
    }
    copy_runtime_auth_state(&src, &dst)?;
    Ok(copied)
}

pub(crate) fn copy_runtime_auth_state(src: &HistoryStore, dst: &HistoryStore) -> Result<()> {
    dst.import_runtime_auth_state(&snapshot_runtime_auth_state(src)?)
}

pub(crate) fn snapshot_runtime_auth_state(src: &HistoryStore) -> Result<RuntimeAuthState> {
    Ok(RuntimeAuthState {
        sessions: src.export_auth_sessions()?,
        logout_tokens: src.export_oidc_logout_tokens()?,
        rate_limits: src.export_auth_rate_limits()?,
    })
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
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let src = config_from_spec(&src_backend, &src_url, retention)?;
    let dst = config_from_spec(&dst_backend, &dst_url, retention)?;
    let copied = migrate_between(&src, &dst)?;
    println!("migrated {copied} delivery history rows and associated runtime state");
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
