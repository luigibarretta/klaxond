use crate::config::{Paths, RuntimeConfig, load_runtime_config};
use anyhow::{Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Ok,
    Warn,
    Error,
    Skipped,
}

#[derive(Serialize)]
struct Check {
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
    let mut offline = false;
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--offline" => offline = true,
            "--json" => json = true,
            "-h" | "--help" => {
                println!("Usage: klaxond doctor [--offline] [--json]");
                return Ok(());
            }
            value => bail!("unknown doctor option: {value}"),
        }
    }

    let paths = match Paths::from_env().resolve_from_config() {
        Ok(paths) => paths,
        Err(error) => {
            return finish(
                vec![check("paths", CheckStatus::Error, error.to_string())],
                json,
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
                json,
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

    if offline {
        checks.push(check(
            "network",
            CheckStatus::Skipped,
            "online probes disabled by --offline",
        ));
    } else {
        online_checks(&cfg, &mut checks).await;
    }

    finish(checks, json)
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

fn channel_checks(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    let public_is_local = url::Url::parse(&cfg.public_url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    checks.push(check(
        "admin authentication",
        if cfg.auth.mode == "none" && !public_is_local {
            CheckStatus::Error
        } else if cfg.auth.mode == "none" {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        if cfg.auth.mode == "none" {
            "disabled; do not expose the admin UI beyond loopback"
        } else {
            "enabled"
        },
    ));
    let ntfy_tokens = cfg
        .ntfy_topics
        .iter()
        .filter(|topic| !topic.token.trim().is_empty())
        .count();
    checks.push(check(
        "ntfy routing",
        if ntfy_tokens > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        format!("{ntfy_tokens} publish-token topic(s) configured"),
    ));
    checks.push(check(
        "Telegram fallback",
        if telegram_ready(cfg) {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        if telegram_ready(cfg) {
            "configured"
        } else {
            "not configured"
        },
    ));
    checks.push(check(
        "SMTP fallback",
        if smtp_ready(cfg) {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        if smtp_ready(cfg) {
            "configured"
        } else {
            "not configured"
        },
    ));
}

async fn online_checks(cfg: &RuntimeConfig, checks: &mut Vec<Check>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            checks.push(check("HTTP client", CheckStatus::Error, error.to_string()));
            return;
        }
    };

    checks.push(
        http_probe(
            &client,
            "public health",
            format!("{}/healthz", cfg.public_url),
        )
        .await,
    );
    checks.push(
        http_probe(
            &client,
            "ntfy health",
            format!("{}/v1/health", cfg.ntfy_url),
        )
        .await,
    );

    if telegram_ready(cfg) {
        let url = format!(
            "{}/bot{}/getMe",
            cfg.telegram_api_base.trim_end_matches('/'),
            cfg.tg_token
        );
        let result = client.get(url).send().await;
        checks.push(response_check("Telegram credentials", result));
    }

    if smtp_ready(cfg) {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect((cfg.smtp_host.as_str(), cfg.smtp_port)),
        )
        .await;
        checks.push(match result {
            Ok(Ok(_)) => check(
                "SMTP connectivity",
                CheckStatus::Ok,
                "TCP connection accepted",
            ),
            Ok(Err(error)) => check("SMTP connectivity", CheckStatus::Error, error.to_string()),
            Err(_) => check(
                "SMTP connectivity",
                CheckStatus::Error,
                "TCP connection timed out",
            ),
        });
    }
}

async fn http_probe(client: &reqwest::Client, name: &str, url: String) -> Check {
    response_check(name, client.get(url).send().await)
}

fn response_check(name: &str, response: reqwest::Result<reqwest::Response>) -> Check {
    match response {
        Ok(response) if response.status().is_success() => {
            check(name, CheckStatus::Ok, response.status().to_string())
        }
        Ok(response) => check(name, CheckStatus::Error, response.status().to_string()),
        Err(error) => check(name, CheckStatus::Error, error.without_url().to_string()),
    }
}

fn telegram_ready(cfg: &RuntimeConfig) -> bool {
    !cfg.tg_token.trim().is_empty() && !cfg.tg_chat.trim().is_empty()
}

fn smtp_ready(cfg: &RuntimeConfig) -> bool {
    [
        cfg.smtp_host.trim(),
        cfg.smtp_user.trim(),
        cfg.smtp_pass.trim(),
        cfg.smtp_from.trim(),
        cfg.smtp_to.trim(),
    ]
    .iter()
    .all(|value| !value.is_empty())
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

fn check(name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) -> Check {
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
