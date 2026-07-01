use crate::config::{Paths, RuntimeConfig, load_runtime_config};
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
}

#[derive(Clone)]
pub struct RenderedImage {
    pub bytes: Vec<u8>,
    pub expires_at: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryEntry {
    pub ts: f64,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub channel: String,
    pub suppressed_by: String,
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
        let session_key = load_or_create_session_key(&paths)?;
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
        })
    }

    pub fn cfg(&self) -> RuntimeConfig {
        read_lock(&self.config, "config").clone()
    }

    pub fn with_cfg<R>(&self, f: impl FnOnce(&RuntimeConfig) -> R) -> R {
        let cfg = read_lock(&self.config, "config");
        f(&cfg)
    }

    pub fn replace_config(&self, cfg: RuntimeConfig) {
        self.cascade_runtime_enabled
            .store(cfg.cascade_default, Ordering::Relaxed);
        *write_lock(&self.config, "config") = cfg;
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
        let mut log = lock_mutex(&self.delivery_log, "delivery log");
        if log.len() == 50 {
            log.pop_front();
        }
        log.push_back(DeliveryEntry {
            ts: crate::util::now_epoch(),
            source: source.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            channel: channel.to_string(),
            suppressed_by: suppressed_by.to_string(),
        });
    }

    pub fn recent_deliveries(&self) -> Vec<DeliveryEntry> {
        lock_mutex(&self.delivery_log, "delivery log")
            .iter()
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

fn load_or_create_session_key(paths: &Paths) -> Result<Vec<u8>> {
    if let Ok(v) = std::env::var("AUTH_SESSION_SECRET")
        && !v.is_empty()
    {
        return Ok(v.into_bytes());
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
