use super::Collector;
use crate::config::{FingerprintConfig, NetworkCollectorConfig, ProcessCollectorConfig};
use crate::event::{Event, EventFactory, NetworkContext, ProcessContext, Severity};
use crate::fingerprint::ExecutableFingerprinter;
use crate::metrics::Metrics;
use crate::platform::{process_snapshots, socket_snapshots, ProcessSnapshot, SocketSnapshot};
use crate::Result;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug)]
pub struct NetworkCollector {
    config: NetworkCollectorConfig,
    process_config: ProcessCollectorConfig,
    fingerprinter: ExecutableFingerprinter,
    previous: HashMap<SocketSnapshot, Option<ProcessContext>>,
    initialized: bool,
}

impl NetworkCollector {
    #[must_use]
    pub fn new(
        config: NetworkCollectorConfig,
        process_config: ProcessCollectorConfig,
        fingerprint: FingerprintConfig,
    ) -> Self {
        Self {
            config,
            process_config,
            fingerprinter: ExecutableFingerprinter::new(fingerprint),
            previous: HashMap::new(),
            initialized: false,
        }
    }

    fn process_map(&self) -> Result<HashMap<u32, ProcessSnapshot>> {
        if !self.config.correlate_processes {
            return Ok(HashMap::new());
        }
        Ok(process_snapshots(&self.process_config)?
            .into_iter()
            .map(|snapshot| (snapshot.pid, snapshot))
            .collect())
    }

    fn correlated_process(
        &mut self,
        socket: &SocketSnapshot,
        processes: &HashMap<u32, ProcessSnapshot>,
        include_fingerprint: bool,
    ) -> Option<ProcessContext> {
        let process = processes.get(&socket.owning_pid?)?;
        let fingerprint = if include_fingerprint && self.config.fingerprint_processes {
            self.fingerprinter.fingerprint(process.executable.as_deref())
        } else {
            None
        };
        Some(process.to_context(fingerprint))
    }

    fn open_event(
        &self,
        factory: &EventFactory,
        socket: &SocketSnapshot,
        process: Option<ProcessContext>,
    ) -> Event {
        let listener = is_listener(socket);
        let kind = if listener {
            "network.listen"
        } else {
            "network.connect"
        };
        let message = if listener {
            format!(
                "new {} listener on {}:{}{}",
                socket.protocol,
                socket.local_address,
                socket.local_port,
                owner_suffix(socket.owning_pid)
            )
        } else {
            format!(
                "new {} socket {}:{} -> {}:{} ({}){}",
                socket.protocol,
                socket.local_address,
                socket.local_port,
                socket.remote_address,
                socket.remote_port,
                socket.state,
                owner_suffix(socket.owning_pid)
            )
        };
        make_network_event(factory, self.name(), kind, Severity::Info, message, socket, process)
    }

    fn close_event(
        &self,
        factory: &EventFactory,
        socket: &SocketSnapshot,
        process: Option<ProcessContext>,
    ) -> Event {
        let listener = is_listener(socket);
        let kind = if listener {
            "network.listener_closed"
        } else {
            "network.closed"
        };
        let message = if listener {
            format!(
                "{} listener closed on {}:{}{}",
                socket.protocol,
                socket.local_address,
                socket.local_port,
                owner_suffix(socket.owning_pid)
            )
        } else {
            format!(
                "{} socket closed {}:{} -> {}:{}{}",
                socket.protocol,
                socket.local_address,
                socket.local_port,
                socket.remote_address,
                socket.remote_port,
                owner_suffix(socket.owning_pid)
            )
        };
        make_network_event(factory, self.name(), kind, Severity::Info, message, socket, process)
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, metrics: &Metrics) -> Result<Vec<Event>> {
        let sockets = socket_snapshots(&self.config)?;
        let socket_set = sockets.iter().cloned().collect::<HashSet<_>>();
        let processes = self.process_map()?;
        let emit_all = !self.initialized && self.config.emit_existing;
        let mut events = Vec::new();

        if self.initialized && self.config.emit_closed {
            for (socket, process) in &self.previous {
                if !socket_set.contains(socket) {
                    events.push(self.close_event(factory, socket, process.clone()));
                }
            }
        }

        let mut current = HashMap::new();
        for socket in sockets {
            let is_new = !self.previous.contains_key(&socket);
            let should_emit = emit_all || (self.initialized && is_new);
            let process = if !is_new {
                self.previous.get(&socket).cloned().flatten()
            } else {
                self.correlated_process(&socket, &processes, should_emit)
            };
            if should_emit {
                if process.is_some() {
                    metrics.increment_correlations();
                }
                events.push(self.open_event(factory, &socket, process.clone()));
            }
            current.insert(socket, process);
        }

        self.previous = current;
        self.initialized = true;
        Ok(events)
    }
}

fn is_listener(socket: &SocketSnapshot) -> bool {
    socket.state == "listen"
        || (socket.protocol.starts_with("udp") && socket.remote_port == 0)
}

fn owner_suffix(pid: Option<u32>) -> String {
    pid.map_or_else(String::new, |value| format!(" owned by pid {value}"))
}

fn make_network_event(
    factory: &EventFactory,
    collector: &str,
    kind: &str,
    severity: Severity,
    message: String,
    socket: &SocketSnapshot,
    process: Option<ProcessContext>,
) -> Event {
    let mut event = factory.event(collector, kind, severity, message);
    event.network = Some(NetworkContext {
        protocol: socket.protocol.clone(),
        local_address: socket.local_address.clone(),
        local_port: socket.local_port,
        remote_address: socket.remote_address.clone(),
        remote_port: socket.remote_port,
        state: socket.state.clone(),
        uid: socket.uid,
        inode: socket.inode,
        owning_pid: socket.owning_pid,
    });
    event.process = process;
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_udp_endpoint_as_listener() {
        let socket = SocketSnapshot {
            protocol: "udp".into(),
            local_address: "0.0.0.0".into(),
            local_port: 53,
            remote_address: "0.0.0.0".into(),
            remote_port: 0,
            state: "unknown".into(),
            uid: None,
            inode: None,
            owning_pid: Some(7),
        };
        assert!(is_listener(&socket));
        assert_eq!(owner_suffix(socket.owning_pid), " owned by pid 7");
    }
}
