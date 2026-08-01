mod auth;
mod filesystem;
mod health;
mod identity;
#[cfg(target_os = "linux")]
mod kernel;
mod network;
mod process;

pub use auth::AuthCollector;
pub use filesystem::FilesystemCollector;
pub use health::HealthCollector;
pub use identity::IdentityCollector;
#[cfg(target_os = "linux")]
pub use kernel::KernelCollector;
pub use network::NetworkCollector;
pub use process::ProcessCollector;

use crate::event::{Event, EventFactory, Severity};
use crate::metrics::Metrics;
use crate::util::sleep_interruptible;
use crate::Result;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub trait Collector: Send {
    fn name(&self) -> &'static str;
    fn interval(&self) -> Duration;
    fn collect(&mut self, factory: &EventFactory, metrics: &Metrics) -> Result<Vec<Event>>;
}

pub fn spawn_collector(
    mut collector: Box<dyn Collector>,
    sender: SyncSender<Event>,
    factory: Arc<EventFactory>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("gargoyle-{}", collector.name()))
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match collector.collect(&factory, &metrics) {
                    Ok(events) => {
                        for event in events {
                            if !send_event(&sender, event, &metrics) {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        metrics.increment_collector_errors();
                        let mut event = factory.event(
                            collector.name(),
                            "collector.error",
                            Severity::Low,
                            format!("collector '{}' failed: {error}", collector.name()),
                        );
                        event.data = json!({ "error": error.to_string() });
                        if !send_event(&sender, event, &metrics) {
                            return;
                        }
                    }
                }
                sleep_interruptible(&stop, collector.interval());
            }
        })
        .expect("collector thread creation should succeed")
}

pub fn send_event(sender: &SyncSender<Event>, event: Event, metrics: &Metrics) -> bool {
    metrics.increment_collected();
    match sender.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            metrics.increment_queue_drops();
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}
