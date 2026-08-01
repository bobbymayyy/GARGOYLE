use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    events_collected: AtomicU64,
    events_emitted: AtomicU64,
    queue_drops: AtomicU64,
    policy_drops: AtomicU64,
    collector_errors: AtomicU64,
    sink_errors: AtomicU64,
    process_correlations: AtomicU64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub events_collected: u64,
    pub events_emitted: u64,
    pub queue_drops: u64,
    pub policy_drops: u64,
    pub collector_errors: u64,
    pub sink_errors: u64,
    pub process_correlations: u64,
}

impl Metrics {
    pub fn increment_collected(&self) {
        let _ = self.events_collected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_emitted(&self) {
        let _ = self.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_queue_drops(&self) {
        let _ = self.queue_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_policy_drops(&self) {
        let _ = self.policy_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_collector_errors(&self) {
        let _ = self.collector_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_sink_errors(&self) {
        let _ = self.sink_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_correlations(&self) {
        let _ = self.process_correlations.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_collected: self.events_collected.load(Ordering::Relaxed),
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            policy_drops: self.policy_drops.load(Ordering::Relaxed),
            collector_errors: self.collector_errors.load(Ordering::Relaxed),
            sink_errors: self.sink_errors.load(Ordering::Relaxed),
            process_correlations: self.process_correlations.load(Ordering::Relaxed),
        }
    }
}
