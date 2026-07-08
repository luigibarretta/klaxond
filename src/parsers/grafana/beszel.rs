use super::super::EmptyStrExt;
use crate::config::RuntimeConfig;
use crate::util::json_get_str;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

pub(super) fn top_containers(
    cfg: &RuntimeConfig,
    host: &str,
    by: &str,
    n: usize,
) -> Option<Vec<(String, f64, &'static str)>> {
    let conn = beszel_open(cfg)?;
    let system_id = beszel_system_id(&conn, host)?;
    let raw: String = conn
        .query_row(
            "SELECT stats FROM container_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        )
        .ok()?;
    let stats: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let mut rows = Vec::new();
    for s in stats {
        let name = json_get_str(&s, "n").if_empty("?").to_string();
        match by {
            "net" => {
                let b = s
                    .get("b")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let tx = b.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                let rx = b.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                rows.push((name, (tx + rx) / 1024.0, "kB/s"));
            }
            "mem" => rows.push((
                name,
                s.get("m").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "MB",
            )),
            _ => rows.push((
                name,
                s.get("c").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "%",
            )),
        }
    }
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
}

pub(super) fn top_containers_global(
    cfg: &RuntimeConfig,
    by: &str,
    n: usize,
) -> Option<Vec<(String, String, f64, &'static str)>> {
    let conn = beszel_open(cfg)?;
    let mut systems_stmt = conn.prepare("SELECT id, name FROM systems").ok()?;
    let systems = systems_stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .ok()?
        .flatten()
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for (system_id, host) in systems {
        let raw: String = match conn.query_row(
            "SELECT stats FROM container_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Ok(stats) = serde_json::from_str::<Vec<Value>>(&raw) else {
            continue;
        };
        for s in stats {
            let name = json_get_str(&s, "n").if_empty("?").to_string();
            if by == "net" {
                let b = s
                    .get("b")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let tx = b.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                let rx = b.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                rows.push((host.clone(), name, (tx + rx) / 1024.0, "kB/s"));
            }
        }
    }
    rows.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
}

pub(super) fn top_filesystems(
    cfg: &RuntimeConfig,
    host: &str,
    n: usize,
) -> Option<Vec<(String, f64, f64, f64)>> {
    let conn = beszel_open(cfg)?;
    let system_id = beszel_system_id(&conn, host)?;
    let raw: String = conn
        .query_row(
            "SELECT stats FROM system_stats WHERE system = ?1 ORDER BY created DESC LIMIT 1",
            [system_id],
            |row| row.get(0),
        )
        .ok()?;
    let stats: Value = serde_json::from_str(&raw).ok()?;
    let mut rows = Vec::new();
    if let (Some(d), Some(du)) = (
        stats.get("d").and_then(|v| v.as_f64()),
        stats.get("du").and_then(|v| v.as_f64()),
    ) {
        let pct = stats
            .get("dp")
            .and_then(|v| v.as_f64())
            .unwrap_or(if d > 0.0 { du / d * 100.0 } else { 0.0 });
        rows.push(("root".to_string(), du, d, pct));
    }
    if let Some(efs) = stats.get("efs").and_then(|v| v.as_object()) {
        for (name, fs) in efs {
            let d = fs.get("d").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let du = fs.get("du").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let pct = if d > 0.0 { du / d * 100.0 } else { 0.0 };
            rows.push((name.clone(), du, d, pct));
        }
    }
    rows.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(n);
    Some(rows)
}

fn beszel_open(cfg: &RuntimeConfig) -> Option<Connection> {
    if !cfg.beszel_db.exists() {
        return None;
    }
    let uri = format!("file:{}?mode=ro&immutable=1", cfg.beszel_db.display());
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn beszel_system_id(conn: &Connection, host: &str) -> Option<i64> {
    conn.query_row(
        "SELECT id FROM systems WHERE name = ?1 OR name LIKE ?2 LIMIT 1",
        (host, format!("%{host}%")),
        |row| row.get::<_, i64>(0),
    )
    .ok()
}
