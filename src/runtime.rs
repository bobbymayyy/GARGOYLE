use crate::collectors::{
    send_event, spawn_collector, AuthCollector, Collector, FilesystemCollector, HealthCollector,
    IdentityCollector, NetworkCollector, ProcessCollector,
};
#[cfg(target_os = "linux")]
use crate::collectors::KernelCollector;
use crate::config::Config;
use crate::event::{EventFactory, Severity};
use crate::metrics::Metrics;
use crate::output::CompositeSink;
use crate::policy::PolicyEngine;
use crate::util::{hostname, sanitize_identifier};
use crate::Result;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn write_policy_event(
    event: crate::event::Event,
    policy: &PolicyEngine,
    sink: &mut CompositeSink,
    metrics: &Metrics,
) {
    let Some(event) = policy.apply(event) else {
        metrics.increment_policy_drops();
        return;
    };
    if let Err(error) = sink.write(&event) {
        metrics.increment_sink_errors();
        eprintln!("GARGOYLE output error: {error}");
    } else {
        metrics.increment_emitted();
    }
}

pub fn run(config: Config) -> Result<()> {
    config.validate()?;
    let host = hostname();
    let raw_agent_id = config
        .agent
        .id
        .clone()
        .unwrap_or_else(|| format!("gargoyle-{host}"));
    let agent_id = sanitize_identifier(&raw_agent_id);
    let factory = Arc::new(EventFactory::new(agent_id, host, config.agent.labels.clone()));
    let metrics = Arc::new(Metrics::default());
    let policy = PolicyEngine::new(config.policy.clone());
    let mut sink = CompositeSink::from_config(&config.output)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = sync_channel(config.agent.queue_capacity);

    let pipeline_metrics = Arc::clone(&metrics);
    let pipeline_factory = Arc::clone(&factory);
    let pipeline = thread::Builder::new()
        .name("gargoyle-pipeline".to_owned())
        .spawn(move || {
            for event in receiver {
                write_policy_event(event, &policy, &mut sink, &pipeline_metrics);
            }

            let mut shutdown = pipeline_factory.event(
                "runtime",
                "agent.stopped",
                Severity::Info,
                "GARGOYLE stopped",
            );
            shutdown.data = json!({ "metrics": pipeline_metrics.snapshot() });
            pipeline_metrics.increment_collected();
            write_policy_event(shutdown, &policy, &mut sink, &pipeline_metrics);
        })?;

    let stop_for_signal = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_for_signal.store(true, Ordering::Relaxed);
    })?;

    let mut startup = factory.event(
        "runtime",
        "agent.started",
        Severity::Info,
        "GARGOYLE is watching",
    );
    startup.data = json!({
        "queue_capacity": config.agent.queue_capacity,
        "pid": std::process::id(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    });
    send_event(&sender, startup, &metrics);

    let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
    if config.collectors.process.enabled {
        collectors.push(Box::new(ProcessCollector::new(
            config.collectors.process.clone(),
            config.collectors.fingerprint.clone(),
        )));
    }
    if config.collectors.network.enabled {
        collectors.push(Box::new(NetworkCollector::new(
            config.collectors.network.clone(),
            config.collectors.process.clone(),
            config.collectors.fingerprint.clone(),
        )));
    }
    if config.collectors.filesystem.enabled {
        collectors.push(Box::new(FilesystemCollector::new(
            config.collectors.filesystem.clone(),
        )));
    }
    if config.collectors.identity.enabled {
        collectors.push(Box::new(IdentityCollector::new(
            config.collectors.identity.clone(),
        )));
    }
    if config.collectors.auth.enabled {
        collectors.push(Box::new(AuthCollector::new(
            config.collectors.auth.clone(),
            config.collectors.fingerprint.clone(),
            config.collectors.process.clone(),
        )));
    }
    #[cfg(target_os = "linux")]
    if config.collectors.kernel.enabled {
        collectors.push(Box::new(KernelCollector::new(
            config.collectors.kernel.clone(),
        )));
    }
    if config.collectors.health.enabled {
        collectors.push(Box::new(HealthCollector::new(
            config.collectors.health.clone(),
        )));
    }

    let handles = collectors
        .into_iter()
        .map(|collector| {
            spawn_collector(
                collector,
                sender.clone(),
                Arc::clone(&factory),
                Arc::clone(&metrics),
                Arc::clone(&stop),
            )
        })
        .collect::<Vec<_>>();

    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(200));
    }

    for handle in handles {
        if handle.join().is_err() {
            metrics.increment_collector_errors();
        }
    }

    drop(sender);

    pipeline
        .join()
        .map_err(|_| std::io::Error::other("pipeline thread terminated unexpectedly"))?;
    Ok(())
}
