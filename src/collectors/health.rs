use super::Collector;
use crate::config::HealthCollectorConfig;
use crate::event::{Event, EventFactory, Severity};
use crate::metrics::Metrics;
use crate::Result;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct HealthCollector {
    config: HealthCollectorConfig,
    started: Instant,
}

impl HealthCollector {
    #[must_use]
    pub fn new(config: HealthCollectorConfig) -> Self {
        Self {
            config,
            started: Instant::now(),
        }
    }
}

impl Collector for HealthCollector {
    fn name(&self) -> &'static str {
        "health"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, metrics: &Metrics) -> Result<Vec<Event>> {
        let mut event = factory.event(
            self.name(),
            "agent.heartbeat",
            Severity::Debug,
            "GARGOYLE heartbeat",
        );
        event.data = json!({
            "uptime_seconds": self.started.elapsed().as_secs(),
            "metrics": metrics.snapshot(),
        });
        Ok(vec![event])
    }
}
