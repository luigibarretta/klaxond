use crate::config::{Paths, RuntimeConfig, load_runtime_config};
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

mod channels;
mod online;

use self::channels::channel_checks;
use self::online::online_checks;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CheckStatus {
    Ok,
    Warn,
    Error,
    Skipped,
}

#[derive(Serialize)]
pub(super) struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
}

#[derive(Serialize)]
struct Report {
    version: &'static str,
    status: &'static str,
    checks: Vec<Check>,
}

pub async fn run_cli(args: &[String]) -> Result<()> {
    let Some(options) = parse_options(args)? else {
        return Ok(());
    };
    let paths = match Paths::from_env().resolve_from_config() {
        Ok(paths) => paths,
        Err(error) => {
            return finish(
                vec![check("paths", CheckStatus::Error, error.to_string())],
                options.json,
            );
        }
    };
    let cfg = match load_runtime_config(&paths) {
        Ok(cfg) => cfg,
        Err(error) => {
            return finish(
                vec![check(
                    "configuration",
                    CheckStatus::Error,
                    error.to_string(),
                )],
                options.json,
            );
        }
    };

    let mut checks = vec![check(
        "configuration",
        CheckStatus::Ok,
        if cfg.emergency.enabled {
            "valid; emergency preflight passed"
        } else {
            "valid; emergency mode is disabled"
        },
    )];
    persistence_checks(&paths, &cfg, &mut checks);
    channel_checks(&cfg, &mut checks);

    if options.offline {
        checks.push(check(
            "network",
            CheckStatus::Skipped,
            "online probes disabled by --offline",
        ));
    } else {
        online_checks(&cfg, &mut checks).await;
    }

    finish(checks, options.json)
}

struct DoctorOptions {
    offline: bool,
    json: bool,
}

fn parse_options(args: &[String]) -> Result<Option<DoctorOptions>> {
    let mut options = DoctorOptions {
        offline: false,
        json: false,
    };
    for arg in args {
        match arg.as_str() {
            "--offline" => options.offline = true,
            "--json" => options.json = true,
            "-h" | "--help" => {
                println!("Usage: klaxond doctor [--offline] [--json]");
                return Ok(None);
            }
            value => bail!("unknown doctor option: {value}"),
        }
    }
    Ok(Some(options))
}

fn persistence_checks(paths: &Paths, cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    checks.push(path_check("configuration file", &paths.config, true));

    let explicit_session_secret = std::env::var("AUTH_SESSION_SECRET")
        .is_ok_and(|value| !value.trim().is_empty())
        || !cfg.auth.session_secret.trim().is_empty();
    if explicit_session_secret {
        checks.push(check(
            "ACK signing key",
            CheckStatus::Ok,
            "persistent session secret is configured",
        ));
    } else if paths.auth_session_key.exists() {
        let status = match fs::metadata(&paths.auth_session_key) {
            Ok(metadata) if metadata.len() >= 32 && private_mode(&metadata) => CheckStatus::Ok,
            Ok(metadata) if metadata.len() < 32 => CheckStatus::Error,
            Ok(_) => CheckStatus::Warn,
            Err(_) => CheckStatus::Error,
        };
        let detail = match status {
            CheckStatus::Ok => "persistent key exists with private permissions",
            CheckStatus::Warn => "persistent key exists but permissions are broader than 0600",
            CheckStatus::Error => "persistent key is unreadable or shorter than 32 bytes",
            CheckStatus::Skipped => unreachable!(),
        };
        checks.push(check("ACK signing key", status, detail));
    } else {
        checks.push(check(
            "ACK signing key",
            CheckStatus::Warn,
            format!(
                "{} will be generated on first server start; keep its parent storage persistent",
                paths.auth_session_key.display()
            ),
        ));
    }

    match cfg.history.backend.as_str() {
        "sqlite" => checks.push(path_check("SQLite history", &paths.history_db, false)),
        "postgres" if cfg.history.postgres_url.trim().is_empty() => checks.push(check(
            "PostgreSQL history",
            CheckStatus::Error,
            "backend is postgres but postgres_url is empty",
        )),
        "postgres" => checks.push(check(
            "PostgreSQL history",
            CheckStatus::Ok,
            "connection URL is configured",
        )),
        other => checks.push(check(
            "history backend",
            CheckStatus::Error,
            format!("unsupported backend: {other}"),
        )),
    }
}

fn path_check(name: &str, path: &Path, must_exist: bool) -> Check {
    if path.exists() {
        return check(name, CheckStatus::Ok, format!("{} exists", path.display()));
    }
    if must_exist {
        return check(
            name,
            CheckStatus::Error,
            format!("{} does not exist", path.display()),
        );
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.exists() {
        check(
            name,
            CheckStatus::Warn,
            format!("{} will be created on first use", path.display()),
        )
    } else {
        check(
            name,
            CheckStatus::Error,
            format!("parent directory {} does not exist", parent.display()),
        )
    }
}

#[cfg(unix)]
fn private_mode(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_mode(_metadata: &fs::Metadata) -> bool {
    true
}

pub(super) fn check(
    name: impl Into<String>,
    status: CheckStatus,
    detail: impl Into<String>,
) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

fn finish(checks: Vec<Check>, json: bool) -> Result<()> {
    let failed = checks
        .iter()
        .any(|check| matches!(check.status, CheckStatus::Error));
    let report = Report {
        version: crate::config::VERSION,
        status: if failed { "error" } else { "ok" },
        checks,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Klaxond {} doctor: {}", report.version, report.status);
        for item in &report.checks {
            let status = match item.status {
                CheckStatus::Ok => "OK",
                CheckStatus::Warn => "WARN",
                CheckStatus::Error => "ERROR",
                CheckStatus::Skipped => "SKIP",
            };
            println!("[{status}] {} — {}", item.name, item.detail);
        }
    }
    if failed {
        bail!("doctor found blocking errors");
    }
    Ok(())
}
