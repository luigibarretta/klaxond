#[cfg(test)]
mod tests;

mod locks;
mod metrics;
mod session;
mod types;

pub use self::locks::{lock_mutex, read_lock, write_lock};
pub use self::metrics::esc_label;
pub use self::types::{
    DedupItem, DedupQueues, PendingMagicLink, PendingOidcState, PendingPasskeyAuthentication,
    PendingPasskeyRegistration, RenderedImage, Suppression,
};
use crate::config::{Paths, RuntimeConfig, load_runtime_config};
use crate::history::{DeliveryEntry, DeliveryPage, HistoryStore};
use crate::util::tmp_path;
use anyhow::{Context, Result};
use fs2::FileExt;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;

use self::metrics::metric_key;
use self::session::load_or_create_session_key;
use self::types::{DeliveryLog, Metrics};

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
    pub delivery_log: Arc<Mutex<DeliveryLog>>,
    pub suppressions: Arc<Mutex<Vec<Suppression>>>,
    pub ack_suppressions: Arc<Mutex<HashMap<String, f64>>>,
    pub active_mutes: Arc<Mutex<HashMap<String, f64>>>,
    pub rendered_images: Arc<Mutex<HashMap<String, RenderedImage>>>,
    pub metrics: Arc<Metrics>,
    pub dedup: Arc<AsyncMutex<DedupQueues>>,
    pub oidc_states: Arc<Mutex<HashMap<String, PendingOidcState>>>,
    pub magic_links: Arc<Mutex<HashMap<String, PendingMagicLink>>>,
    pub passkey_registrations: Arc<Mutex<HashMap<String, PendingPasskeyRegistration>>>,
    pub passkey_authentications: Arc<Mutex<HashMap<String, PendingPasskeyAuthentication>>>,
    pub auth_failures: auth_modules::rate_limit::InMemoryRateLimiter,
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
            delivery_log: Arc::new(Mutex::new(DeliveryLog::with_capacity(50))),
            suppressions: Arc::new(Mutex::new(Vec::new())),
            ack_suppressions: Arc::new(Mutex::new(HashMap::new())),
            active_mutes: Arc::new(Mutex::new(HashMap::new())),
            rendered_images: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            dedup: Arc::new(AsyncMutex::new(queues)),
            oidc_states: Arc::new(Mutex::new(HashMap::new())),
            magic_links: Arc::new(Mutex::new(HashMap::new())),
            passkey_registrations: Arc::new(Mutex::new(HashMap::new())),
            passkey_authentications: Arc::new(Mutex::new(HashMap::new())),
            auth_failures: auth_modules::rate_limit::InMemoryRateLimiter::default(),
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
