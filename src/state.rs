use crate::config::{Paths, RuntimeConfig, load_runtime_config};
use crate::history::{DeliveryEntry, DeliveryPage, HistoryStore};
use crate::util::{atomic_write, random_bytes, tmp_path};
use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Uuid};

#[derive(Clone)]
pub struct AppState {
    pub paths: Paths,
    pub http: reqwest::Client,
    pub started: Instant,
    pub config: Arc<RwLock<RuntimeConfig>>,
    pub config_write_lock: Arc<Mutex<()>>,
    pub session_key: Arc<Vec<u8>>,
    pub cascade_runtime_enabled: Arc<AtomicBool>,
    pub history: Arc<RwLock<Arc<HistoryStore>>>,
    pub delivery_log: Arc<Mutex<VecDeque<DeliveryEntry>>>,
    pub suppressions: Arc<Mutex<Vec<Suppression>>>,
    pub ack_suppressions: Arc<Mutex<HashMap<String, f64>>>,
    pub active_mutes: Arc<Mutex<HashMap<String, f64>>>,
    pub rendered_images: Arc<Mutex<HashMap<String, RenderedImage>>>,
    pub metrics: Arc<Metrics>,
    pub dedup: Arc<AsyncMutex<DedupQueues>>,
    pub oidc_states: Arc<Mutex<HashMap<String, (f64, String)>>>,
    pub passkey_registrations: Arc<Mutex<HashMap<String, PendingPasskeyRegistration>>>,
    pub passkey_authentications: Arc<Mutex<HashMap<String, PendingPasskeyAuthentication>>>,
    pub auth_failures: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

#[derive(Clone)]
pub struct RenderedImage {
    pub bytes: Vec<u8>,
    pub expires_at: f64,
}

#[derive(Clone, Debug)]
pub struct Suppression {
    pub rule_idx: usize,
    pub anchor: Option<String>,
    pub expiry: f64,
}

#[derive(Default)]
pub struct Metrics {
    pub counters: Mutex<HashMap<String, i64>>,
    pub gauges: Mutex<HashMap<String, f64>>,
}

#[derive(Default, Debug)]
pub struct DedupQueues {
    pub queues: HashMap<String, Vec<DedupItem>>,
    pub timer_active: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DedupItem {
    pub ts: f64,
    pub source: String,
    pub severity: String,
    pub payload: Value,
    pub parts: crate::parsers::Parts,
    pub common_labels: HashMap<String, String>,
    pub with_cascade: bool,
    pub dedup_key: String,
}

#[derive(Clone, Debug)]
pub struct PendingPasskeyRegistration {
    pub ts: f64,
    pub user_sub: String,
    pub user_name: String,
    pub user_email: String,
    pub user_uuid: Uuid,
    pub label: String,
    pub state: PasskeyRegistration,
}

#[derive(Clone, Debug)]
pub struct PendingPasskeyAuthentication {
    pub ts: f64,
    pub user_sub: String,
    pub state: PasskeyAuthentication,
}

impl AppState {
    pub fn new(paths: Paths) -> Result<Self> {
        let cfg = load_runtime_config(&paths)?;
        let cascade_runtime_enabled = cfg.cascade_default;
        let session_key = load_or_create_session_key(&paths, &cfg)?;
        let history = Arc::new(HistoryStore::open(&cfg.history)?);
        let mut queues = DedupQueues::default();
        for src in crate::config::DEDUP_SOURCES {
            queues.queues.insert((*src).to_string(), Vec::new());
            queues.timer_active.insert((*src).to_string(), false);
        }
        Ok(Self {
            paths,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build reqwest client")?,
            started: Instant::now(),
            config: Arc::new(RwLock::new(cfg)),
            config_write_lock: Arc::new(Mutex::new(())),
            session_key: Arc::new(session_key),
            cascade_runtime_enabled: Arc::new(AtomicBool::new(cascade_runtime_enabled)),
            history: Arc::new(RwLock::new(history)),
            delivery_log: Arc::new(Mutex::new(VecDeque::with_capacity(50))),
            suppressions: Arc::new(Mutex::new(Vec::new())),
            ack_suppressions: Arc::new(Mutex::new(HashMap::new())),
            active_mutes: Arc::new(Mutex::new(HashMap::new())),
            rendered_images: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            dedup: Arc::new(AsyncMutex::new(queues)),
            oidc_states: Arc::new(Mutex::new(HashMap::new())),
            passkey_registrations: Arc::new(Mutex::new(HashMap::new())),
            passkey_authentications: Arc::new(Mutex::new(HashMap::new())),
            auth_failures: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn cfg(&self) -> RuntimeConfig {
        read_lock(&self.config, "config").clone()
    }

    pub fn with_cfg<R>(&self, f: impl FnOnce(&RuntimeConfig) -> R) -> R {
        let cfg = read_lock(&self.config, "config");
        f(&cfg)
    }

    pub fn try_replace_config(&self, cfg: RuntimeConfig) -> Result<(), String> {
        self.replace_history_store_if_needed(&cfg)?;
        self.cascade_runtime_enabled
            .store(cfg.cascade_default, Ordering::Relaxed);
        *write_lock(&self.config, "config") = cfg;
        Ok(())
    }

    pub fn replace_config(&self, cfg: RuntimeConfig) {
        if let Err(err) = self.try_replace_config(cfg) {
            tracing::error!("failed to replace runtime config: {err}");
        }
    }

    pub fn try_replace_config_preserving_runtime(&self, cfg: RuntimeConfig) -> Result<(), String> {
        self.replace_history_store_if_needed(&cfg)?;
        *write_lock(&self.config, "config") = cfg;
        Ok(())
    }

    pub fn replace_config_preserving_runtime(&self, cfg: RuntimeConfig) {
        if let Err(err) = self.try_replace_config_preserving_runtime(cfg) {
            tracing::error!("failed to replace runtime config: {err}");
        }
    }

    fn replace_history_store_if_needed(&self, cfg: &RuntimeConfig) -> Result<(), String> {
        let current = self.with_cfg(|current| current.history.clone());
        if current == cfg.history {
            return Ok(());
        }
        let store = HistoryStore::open(&cfg.history).map_err(|err| err.to_string())?;
        *write_lock(&self.history, "history store") = Arc::new(store);
        Ok(())
    }

    fn history_store(&self) -> Arc<HistoryStore> {
        read_lock(&self.history, "history store").clone()
    }

    pub fn with_config_write_lock<R>(&self, f: impl FnOnce() -> R) -> Result<R, String> {
        let _guard = lock_mutex(&self.config_write_lock, "config writes");
        if let Some(parent) = self.paths.config.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create config dir: {err}"))?;
        }
        let lock_path = tmp_path(&self.paths.config, "lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|err| format!("open {}: {err}", lock_path.display()))?;
        lock.lock_exclusive()
            .map_err(|err| format!("lock {}: {err}", lock_path.display()))?;
        let result = f();
        if let Err(err) = lock.unlock() {
            tracing::error!("unlock {} failed: {err}", lock_path.display());
        }
        Ok(result)
    }

    pub fn log_delivery(
        &self,
        source: &str,
        severity: &str,
        title: &str,
        channel: &str,
        suppressed_by: &str,
    ) {
        let entry = DeliveryEntry {
            ts: crate::util::now_epoch(),
            source: source.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            channel: channel.to_string(),
            suppressed_by: suppressed_by.to_string(),
        };
        if let Err(err) = self.history_store().record_delivery(&entry) {
            tracing::error!("persist delivery history failed: {err}");
        }
        let mut log = lock_mutex(&self.delivery_log, "delivery log");
        if log.len() == 50 {
            log.pop_front();
        }
        log.push_back(entry);
    }

    pub fn recent_deliveries(&self) -> Vec<DeliveryEntry> {
        let limit = self.with_cfg(|cfg| cfg.history.default_limit);
        match self.history_store().deliveries_page(limit, 0) {
            Ok(page) => page.entries,
            Err(err) => {
                tracing::error!("read delivery history failed: {err}");
                self.recent_deliveries_from_memory()
            }
        }
    }

    pub fn deliveries_page(&self, limit: usize, offset: usize) -> DeliveryPage {
        match self.history_store().deliveries_page(limit, offset) {
            Ok(page) => page,
            Err(err) => {
                tracing::error!("read paginated delivery history failed: {err}");
                let entries = self
                    .recent_deliveries_from_memory()
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>();
                DeliveryPage {
                    total: lock_mutex(&self.delivery_log, "delivery log").len(),
                    entries,
                    limit,
                    offset,
                }
            }
        }
    }

    fn recent_deliveries_from_memory(&self) -> Vec<DeliveryEntry> {
        lock_mutex(&self.delivery_log, "delivery log")
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn metric_inc(&self, name: &str, labels: &[(&str, &str)], by: i64) {
        let key = metric_key(name, labels);
        let mut counters = lock_mutex(&self.metrics.counters, "metrics counters");
        *counters.entry(key).or_insert(0) += by;
    }

    pub fn metric_set(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        let key = metric_key(name, labels);
        lock_mutex(&self.metrics.gauges, "metrics gauges").insert(key, value);
    }
}

pub fn lock_mutex<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        tracing::error!("recovering poisoned mutex: {name}");
        poisoned.into_inner()
    })
}

pub fn read_lock<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|poisoned| {
        tracing::error!("recovering poisoned rwlock read: {name}");
        poisoned.into_inner()
    })
}

pub fn write_lock<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|poisoned| {
        tracing::error!("recovering poisoned rwlock write: {name}");
        poisoned.into_inner()
    })
}

fn metric_key(name: &str, labels: &[(&str, &str)]) -> String {
    let mut l = labels
        .iter()
        .map(|(k, v)| format!("{k}={}", esc_label(v)))
        .collect::<Vec<_>>();
    l.sort();
    format!("{name}|{}", l.join(","))
}

pub fn esc_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn load_or_create_session_key(paths: &Paths, cfg: &RuntimeConfig) -> Result<Vec<u8>> {
    if let Ok(v) = std::env::var("AUTH_SESSION_SECRET")
        && !v.is_empty()
    {
        return Ok(v.into_bytes());
    }
    if !cfg.auth.session_secret.trim().is_empty() {
        return Ok(cfg.auth.session_secret.as_bytes().to_vec());
    }
    if let Some(secret) = cfg
        .toml
        .get("auth")
        .and_then(|v| v.get("session_secret"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
    {
        return Ok(secret.as_bytes().to_vec());
    }
    if paths.auth_session_key.exists() {
        return fs::read(&paths.auth_session_key)
            .with_context(|| format!("read {}", paths.auth_session_key.display()));
    }
    let key = random_bytes::<32>().to_vec();
    if let Some(parent) = paths.auth_session_key.parent() {
        fs::create_dir_all(parent).ok();
    }
    atomic_write(&paths.auth_session_key, &key)?;
    set_private_mode(&paths.auth_session_key);
    Ok(key)
}

#[cfg(unix)]
fn set_private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_paths(tmp: &TempDir) -> Paths {
        let data = tmp.path();
        Paths {
            config: data.join("klaxond.toml"),
            default_config: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("klaxond.default.toml"),
            render_config: data.join("render-config.json"),
            ntfy_topics: data.join("ntfy-topics.json"),
            dedup_config: data.join("dedup-config.json"),
            dedup_pending_dir: data.join("dedup_pending"),
            auth_config: data.join("auth-config.json"),
            auth_session_key: data.join("auth-session.key"),
            backup_dir: data.join("backups"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            beszel_db: data.join("missing-beszel.db"),
            history_db: data.join("klaxond.db"),
        }
    }

    #[test]
    fn auth_session_secret_can_come_from_toml_without_key_file() {
        // SAFETY: this test is single-threaded with respect to its env mutation.
        unsafe { std::env::remove_var("AUTH_SESSION_SECRET") };
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        fs::write(
            &paths.config,
            r#"
[auth]
session_secret = "toml-session-secret"
"#,
        )
        .unwrap();

        let cfg = load_runtime_config(&paths).unwrap();
        let key = load_or_create_session_key(&paths, &cfg).unwrap();

        assert_eq!(key, b"toml-session-secret");
        assert!(!paths.auth_session_key.exists());
    }

    #[test]
    fn delivery_history_survives_state_recreation() {
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        let state = AppState::new(paths.clone()).unwrap();
        state.log_delivery("grafana", "warning", "Persist me", "dry-run", "");
        state.log_delivery("grafana", "warning", "Newest", "dry-run", "");
        drop(state);

        let reloaded = AppState::new(paths).unwrap();
        let deliveries = reloaded.recent_deliveries();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(deliveries[0].title, "Newest");
        assert_eq!(deliveries[0].source, "grafana");
    }

    #[test]
    fn history_store_reopens_when_runtime_config_changes() {
        let tmp = TempDir::new().unwrap();
        let paths = temp_paths(&tmp);
        let state = AppState::new(paths).unwrap();
        state.log_delivery("grafana", "warning", "Original DB", "dry-run", "");

        let mut cfg = state.cfg();
        cfg.history.sqlite_path = tmp.path().join("next.db");
        state.try_replace_config(cfg).unwrap();
        state.log_delivery("grafana", "warning", "Next DB", "dry-run", "");

        let deliveries = state.recent_deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].title, "Next DB");
    }
}
