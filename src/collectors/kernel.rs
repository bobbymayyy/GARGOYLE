use super::Collector;
use crate::config::KernelCollectorConfig;
use crate::event::{Event, EventFactory, KernelContext, Severity};
use crate::metrics::Metrics;
use crate::util::read_string_limited_checked;
use crate::Result;
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct KernelCollector {
    config: KernelCollectorConfig,
    modules: HashSet<String>,
    taint: Option<u64>,
    lockdown: Option<String>,
    initialized: bool,
}

impl KernelCollector {
    #[must_use]
    pub fn new(config: KernelCollectorConfig) -> Self {
        Self {
            config,
            modules: HashSet::new(),
            taint: None,
            lockdown: None,
            initialized: false,
        }
    }

    fn read_modules() -> Result<HashSet<String>> {
        Ok(read_string_limited_checked("/proc/modules", 4 * 1024 * 1024)?
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_owned)
            .collect())
    }

    fn read_taint() -> Result<Option<u64>> {
        let value = read_string_limited_checked("/proc/sys/kernel/tainted", 4096)?;
        Ok(Some(value.trim().parse()?))
    }

    fn read_lockdown() -> Result<Option<String>> {
        let path = Path::new("/sys/kernel/security/lockdown");
        if !path.exists() {
            return Ok(None);
        }
        let value = read_string_limited_checked(path, 4096)?;
        let value = value.trim().to_owned();
        Ok((!value.is_empty()).then_some(value))
    }
}

impl Collector for KernelCollector {
    fn name(&self) -> &'static str {
        "kernel"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
        let modules = Self::read_modules()?;
        let taint = Self::read_taint()?;
        let lockdown = Self::read_lockdown()?;
        let emit_all = !self.initialized && self.config.emit_existing;
        let mut events = Vec::new();

        for module in &modules {
            if emit_all || (self.initialized && !self.modules.contains(module)) {
                let mut event = factory.event(
                    self.name(),
                    "kernel.module_loaded",
                    Severity::High,
                    format!("kernel module loaded: {module}"),
                );
                event.kernel = Some(KernelContext {
                    module: Some(module.clone()),
                    taint,
                    lockdown: lockdown.clone(),
                });
                events.push(event);
            }
        }
        if self.initialized {
            for module in &self.modules {
                if !modules.contains(module) {
                    let mut event = factory.event(
                        self.name(),
                        "kernel.module_unloaded",
                        Severity::Medium,
                        format!("kernel module unloaded: {module}"),
                    );
                    event.kernel = Some(KernelContext {
                        module: Some(module.clone()),
                        taint,
                        lockdown: lockdown.clone(),
                    });
                    events.push(event);
                }
            }
            if taint != self.taint {
                let mut event = factory.event(
                    self.name(),
                    "kernel.taint_changed",
                    Severity::High,
                    format!("kernel taint changed from {:?} to {:?}", self.taint, taint),
                );
                event.kernel = Some(KernelContext {
                    module: None,
                    taint,
                    lockdown: lockdown.clone(),
                });
                event.data = json!({ "previous_taint": self.taint, "current_taint": taint });
                events.push(event);
            }
            if lockdown != self.lockdown {
                let mut event = factory.event(
                    self.name(),
                    "kernel.lockdown_changed",
                    Severity::High,
                    "kernel lockdown state changed",
                );
                event.kernel = Some(KernelContext {
                    module: None,
                    taint,
                    lockdown: lockdown.clone(),
                });
                event.data = json!({
                    "previous_lockdown": self.lockdown,
                    "current_lockdown": lockdown,
                });
                events.push(event);
            }
        }

        self.modules = modules;
        self.taint = taint;
        self.lockdown = lockdown;
        self.initialized = true;
        Ok(events)
    }
}
