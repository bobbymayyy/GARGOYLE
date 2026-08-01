use super::Collector;
use crate::config::{FingerprintConfig, ProcessCollectorConfig};
use crate::event::{Event, EventFactory, ProcessContext, Severity};
use crate::fingerprint::ExecutableFingerprinter;
use crate::metrics::Metrics;
use crate::platform::{process_snapshots, ProcessSnapshot};
use crate::Result;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug)]
pub struct ProcessCollector {
    config: ProcessCollectorConfig,
    fingerprinter: ExecutableFingerprinter,
    previous: HashMap<u32, TrackedProcess>,
    initialized: bool,
}

#[derive(Debug, Clone)]
struct TrackedProcess {
    start_key: String,
    context: ProcessContext,
}

impl ProcessCollector {
    #[must_use]
    pub fn new(config: ProcessCollectorConfig, fingerprint: FingerprintConfig) -> Self {
        Self {
            config,
            fingerprinter: ExecutableFingerprinter::new(fingerprint),
            previous: HashMap::new(),
            initialized: false,
        }
    }

    fn track(&mut self, snapshot: &ProcessSnapshot, include_fingerprint: bool) -> TrackedProcess {
        let fingerprint = if include_fingerprint {
            self.fingerprinter.fingerprint(snapshot.executable.as_deref())
        } else {
            None
        };
        TrackedProcess {
            start_key: snapshot.start_key.clone(),
            context: snapshot.to_context(fingerprint),
        }
    }

    fn start_event(&self, factory: &EventFactory, context: ProcessContext) -> Event {
        let display = context
            .name
            .as_deref()
            .or(context.executable.as_deref())
            .unwrap_or("unknown");
        let mut event = factory.event(
            self.name(),
            "process.start",
            Severity::Info,
            format!("process started: {display} (pid {})", context.pid),
        );
        event.process = Some(context);
        event
    }

    fn stop_event(&self, factory: &EventFactory, context: ProcessContext) -> Event {
        let display = context
            .name
            .as_deref()
            .or(context.executable.as_deref())
            .unwrap_or("unknown");
        let mut event = factory.event(
            self.name(),
            "process.stop",
            Severity::Info,
            format!("process stopped: {display} (pid {})", context.pid),
        );
        event.process = Some(context);
        event
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
        let snapshots = process_snapshots(&self.config)?;
        let snapshot_keys: HashMap<u32, String> = snapshots
            .iter()
            .map(|snapshot| (snapshot.pid, snapshot.start_key.clone()))
            .collect();
        let emit_all = !self.initialized && self.config.emit_existing;
        let mut events = Vec::new();

        if self.initialized && self.config.emit_stops {
            for (pid, tracked) in &self.previous {
                let same_process = snapshot_keys.get(pid) == Some(&tracked.start_key);
                if !same_process {
                    events.push(self.stop_event(factory, tracked.context.clone()));
                }
            }
        }

        let mut current = HashMap::new();
        for snapshot in snapshots {
            let is_new = self
                .previous
                .get(&snapshot.pid)
                .is_none_or(|previous| previous.start_key != snapshot.start_key);
            let should_emit = emit_all || (self.initialized && is_new);
            let tracked = match (is_new, self.previous.get(&snapshot.pid).cloned()) {
                (false, Some(previous)) => previous,
                _ => self.track(&snapshot, should_emit),
            };
            if should_emit {
                events.push(self.start_event(factory, tracked.context.clone()));
            }
            current.insert(snapshot.pid, tracked);
        }

        self.previous = current;
        self.initialized = true;
        Ok(events)
    }
}
