pub(crate) fn read_history(toml: &toml::Value, paths: &Paths) -> HistoryConfig {
    let history = toml_get(toml, &["history"]);
    let backend = std::env::var("KLAXOND_HISTORY_BACKEND")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            history
                .and_then(|v| v.get("backend"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "sqlite".to_string())
        .trim()
        .to_ascii_lowercase();
    let postgres_url = std::env::var("KLAXOND_POSTGRES_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            history
                .and_then(|v| v.get("postgres_url"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let retention = std::env::var("KLAXOND_HISTORY_RETENTION")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| {
            history
                .and_then(|v| v.get("retention"))
                .and_then(|v| v.as_integer())
                .map(|v| v.max(0) as usize)
        })
        .unwrap_or(5000);
    let default_limit = std::env::var("KLAXOND_HISTORY_DEFAULT_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| {
            history
                .and_then(|v| v.get("default_limit"))
                .and_then(|v| v.as_integer())
                .map(|v| v.max(1) as usize)
        })
        .unwrap_or(500)
        .clamp(1, 10_000);
    HistoryConfig {
        backend,
        sqlite_path: paths.history_db.clone(),
        postgres_url,
        retention,
        default_limit,
    }
}
use super::super::{HistoryConfig, Paths};
use crate::util::toml_get;
