use super::bootstrap_config;
use crate::util::toml_get;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub default_config: PathBuf,
    pub render_config: PathBuf,
    pub ntfy_topics: PathBuf,
    pub dedup_config: PathBuf,
    pub dedup_pending_dir: PathBuf,
    pub auth_config: PathBuf,
    pub auth_session_key: PathBuf,
    pub backup_dir: PathBuf,
    pub static_dir: PathBuf,
    pub beszel_db: PathBuf,
    pub history_db: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let default_config = if Path::new("/app/klaxond.default.toml").exists() {
            PathBuf::from("/app/klaxond.default.toml")
        } else {
            PathBuf::from("klaxond.default.toml")
        };
        let static_dir = if Path::new("/app/static").is_dir() {
            PathBuf::from("/app/static")
        } else {
            PathBuf::from("static")
        };
        Self {
            config: PathBuf::from(
                std::env::var("KLAXOND_CONFIG").unwrap_or_else(|_| "/data/klaxond.toml".into()),
            ),
            default_config,
            render_config: PathBuf::from(
                std::env::var("RENDER_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/render-config.json".into()),
            ),
            ntfy_topics: PathBuf::from(
                std::env::var("NTFY_TOPICS_PATH")
                    .unwrap_or_else(|_| "/data/ntfy-topics.json".into()),
            ),
            dedup_config: PathBuf::from(
                std::env::var("DEDUP_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/dedup-config.json".into()),
            ),
            dedup_pending_dir: PathBuf::from(
                std::env::var("DEDUP_PENDING_DIR").unwrap_or_else(|_| "/data/dedup_pending".into()),
            ),
            auth_config: PathBuf::from(
                std::env::var("AUTH_CONFIG_PATH")
                    .unwrap_or_else(|_| "/data/auth-config.json".into()),
            ),
            auth_session_key: PathBuf::from(
                std::env::var("AUTH_SESSION_KEY_PATH")
                    .unwrap_or_else(|_| "/data/auth-session.key".into()),
            ),
            backup_dir: PathBuf::from(
                std::env::var("KLAXOND_BACKUP_DIR").unwrap_or_else(|_| "/data/backups".into()),
            ),
            static_dir,
            beszel_db: PathBuf::from(
                std::env::var("BESZEL_DB_PATH").unwrap_or_else(|_| "/beszel_data/data.db".into()),
            ),
            history_db: PathBuf::from(
                std::env::var("KLAXOND_SQLITE_PATH").unwrap_or_else(|_| "/data/klaxond.db".into()),
            ),
        }
    }

    pub fn resolve_from_config(mut self) -> Result<Self> {
        bootstrap_config(&self)?;
        let toml_text = fs::read_to_string(&self.config).unwrap_or_default();
        let toml: toml::Value = toml::from_str(&toml_text)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
        let config_dir = self.config.parent().unwrap_or_else(|| Path::new("."));
        apply_toml_path(
            &mut self.render_config,
            "RENDER_CONFIG_PATH",
            toml_get(&toml, &["paths", "render_config"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.ntfy_topics,
            "NTFY_TOPICS_PATH",
            toml_get(&toml, &["paths", "ntfy_topics"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.dedup_config,
            "DEDUP_CONFIG_PATH",
            toml_get(&toml, &["paths", "dedup_config"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.auth_config,
            "AUTH_CONFIG_PATH",
            toml_get(&toml, &["paths", "auth_config"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.auth_session_key,
            "AUTH_SESSION_KEY_PATH",
            toml_get(&toml, &["paths", "auth_session_key"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.backup_dir,
            "KLAXOND_BACKUP_DIR",
            toml_get(&toml, &["paths", "backup_dir"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.dedup_pending_dir,
            "DEDUP_PENDING_DIR",
            toml_get(&toml, &["paths", "dedup_pending_dir"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.beszel_db,
            "BESZEL_DB_PATH",
            toml_get(&toml, &["paths", "beszel_db"]),
            config_dir,
        );
        apply_toml_path(
            &mut self.history_db,
            "KLAXOND_SQLITE_PATH",
            toml_get(&toml, &["paths", "history_db"]),
            config_dir,
        );
        Ok(self)
    }
}

fn apply_toml_path(
    target: &mut PathBuf,
    env_key: &str,
    value: Option<&toml::Value>,
    config_dir: &Path,
) {
    if std::env::var_os(env_key).is_some() {
        return;
    }
    let Some(path) = value
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
    else {
        return;
    };
    let path = PathBuf::from(path);
    *target = if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    };
}
