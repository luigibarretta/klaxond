use super::{AppState, lock_mutex};
use crate::history::{
    DeliveryActivity, DeliveryEntry, DeliveryPage, DeliveryQuery, RepeatSuppressionSummary,
};
use anyhow::Result;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const DELIVERY_ACTIVITY_CACHE_TTL: Duration = Duration::from_secs(5);

impl AppState {
    pub fn log_delivery(
        &self,
        source: &str,
        severity: &str,
        title: &str,
        channel: &str,
        suppressed_by: &str,
    ) {
        self.log_delivery_with_receipt(source, severity, title, channel, suppressed_by, None);
    }

    pub fn log_delivery_with_receipt(
        &self,
        source: &str,
        severity: &str,
        title: &str,
        channel: &str,
        suppressed_by: &str,
        emergency_receipt_id: Option<&str>,
    ) {
        let entry = DeliveryEntry {
            ts: crate::util::now_epoch(),
            source: source.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            channel: channel.to_string(),
            suppressed_by: suppressed_by.to_string(),
            emergency_receipt_id: emergency_receipt_id.map(str::to_string),
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
        self.query_deliveries(&DeliveryQuery::page(limit, offset))
    }

    pub fn query_deliveries(&self, query: &DeliveryQuery) -> DeliveryPage {
        let query = query.normalized();
        match self.history_store().query_deliveries(&query) {
            Ok(page) => page,
            Err(err) => {
                tracing::error!("read paginated delivery history failed: {err}");
                let filtered = self
                    .recent_deliveries_from_memory()
                    .into_iter()
                    .filter(|entry| query.matches(entry))
                    .collect::<Vec<_>>();
                let total = filtered.len();
                let entries = filtered
                    .into_iter()
                    .skip(query.offset)
                    .take(query.limit)
                    .collect();
                DeliveryPage {
                    total,
                    entries,
                    limit: query.limit,
                    offset: query.offset,
                }
            }
        }
    }

    pub fn delivery_activity(&self, hours: u16, now: f64) -> Result<DeliveryActivity> {
        let hours = hours.clamp(1, 168);
        let since = now - f64::from(hours) * 3_600.0;
        self.history_store().delivery_activity(hours, since, now)
    }

    pub(crate) fn history_generation(&self) -> u64 {
        self.history_generation.load(Ordering::SeqCst)
    }

    pub(crate) fn cached_delivery_activity(
        &self,
        hours: u16,
        generation: u64,
    ) -> Option<DeliveryActivity> {
        lock_mutex(&self.delivery_activity_cache, "delivery activity cache")
            .get(&hours)
            .filter(|(cached_at, cached_generation, _)| {
                *cached_generation == generation
                    && cached_at.elapsed() <= DELIVERY_ACTIVITY_CACHE_TTL
            })
            .map(|(_, _, activity)| activity.clone())
    }

    pub(crate) fn cache_delivery_activity(
        &self,
        generation: u64,
        activity: DeliveryActivity,
    ) -> bool {
        let mut cache = lock_mutex(&self.delivery_activity_cache, "delivery activity cache");
        if self.history_generation() != generation {
            return false;
        }
        cache.insert(activity.hours, (Instant::now(), generation, activity));
        true
    }

    pub fn recent_repeat_suppressions(&self, limit: usize) -> Vec<RepeatSuppressionSummary> {
        match self.history_store().recent_repeat_suppressions(limit) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::error!("read repeat suppression history failed: {err}");
                Vec::new()
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
}
