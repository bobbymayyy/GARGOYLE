use super::Collector;
use crate::config::IdentityCollectorConfig;
use crate::event::{Event, EventFactory, Severity};
use crate::metrics::Metrics;
use crate::platform::{identity_snapshots, IdentitySnapshot};
use crate::Result;
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

type IdentityKey = (String, String);

#[derive(Debug)]
pub struct IdentityCollector {
    config: IdentityCollectorConfig,
    previous: HashMap<IdentityKey, IdentitySnapshot>,
    initialized: bool,
}

impl IdentityCollector {
    #[must_use]
    pub fn new(config: IdentityCollectorConfig) -> Self {
        Self {
            config,
            previous: HashMap::new(),
            initialized: false,
        }
    }

    fn event(
        &self,
        factory: &EventFactory,
        snapshot: &IdentitySnapshot,
        operation: &str,
    ) -> Event {
        let kind = format!("identity.{}_{}", snapshot.object_type, operation);
        let severity = identity_severity(snapshot, operation);
        let mut event = factory.event(
            self.name(),
            kind,
            severity,
            format!(
                "local {} {}: {}",
                snapshot.object_type,
                operation.replace('_', " "),
                snapshot.name
            ),
        );
        event.identity = Some(snapshot.to_context(operation));
        event
    }
}

impl Collector for IdentityCollector {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
        let snapshots = identity_snapshots(&self.config)?;
        let current = snapshots
            .into_iter()
            .map(|snapshot| (snapshot.key(), snapshot))
            .collect::<HashMap<_, _>>();
        let mut events = Vec::new();

        if !self.initialized {
            if self.config.emit_existing {
                for snapshot in current.values() {
                    events.push(self.event(factory, snapshot, "observed"));
                }
            }
        } else {
            for (key, previous) in &self.previous {
                match current.get(key) {
                    None => events.push(self.event(factory, previous, "removed")),
                    Some(now) if now != previous => {
                        let operation = if only_members_changed(previous, now) {
                            "membership_changed"
                        } else {
                            "changed"
                        };
                        let mut event = self.event(factory, now, operation);
                        if operation == "membership_changed" {
                            let (added, removed) = membership_delta(previous, now);
                            event.data = json!({
                                "added_members": added,
                                "removed_members": removed,
                            });
                        }
                        events.push(event);
                    }
                    Some(_) => {}
                }
            }
            for (key, snapshot) in &current {
                if !self.previous.contains_key(key) {
                    events.push(self.event(factory, snapshot, "added"));
                }
            }
        }

        events.sort_by(|left, right| left.kind.cmp(&right.kind).then(left.message.cmp(&right.message)));
        self.previous = current;
        self.initialized = true;
        Ok(events)
    }
}

fn only_members_changed(previous: &IdentitySnapshot, current: &IdentitySnapshot) -> bool {
    previous.object_type == "group"
        && current.object_type == "group"
        && previous.members != current.members
        && previous.name == current.name
        && previous.numeric_id == current.numeric_id
        && previous.sid == current.sid
        && previous.primary_group_id == current.primary_group_id
        && previous.domain == current.domain
        && previous.home == current.home
        && previous.shell == current.shell
        && previous.enabled == current.enabled
}

fn membership_delta(
    previous: &IdentitySnapshot,
    current: &IdentitySnapshot,
) -> (Vec<String>, Vec<String>) {
    let previous = previous.members.iter().cloned().collect::<BTreeSet<_>>();
    let current = current.members.iter().cloned().collect::<BTreeSet<_>>();
    let added = current.difference(&previous).cloned().collect();
    let removed = previous.difference(&current).cloned().collect();
    (added, removed)
}

fn identity_severity(snapshot: &IdentitySnapshot, operation: &str) -> Severity {
    let privileged_group = snapshot.object_type == "group"
        && matches!(
            snapshot.name.to_ascii_lowercase().as_str(),
            "administrators" | "sudo" | "wheel"
        );
    if privileged_group && matches!(
            operation,
            "added" | "removed" | "changed" | "membership_changed"
        ) {
        Severity::High
    } else if snapshot.object_type == "user" && matches!(operation, "added" | "removed") {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(object_type: &str, name: &str) -> IdentitySnapshot {
        IdentitySnapshot {
            object_type: object_type.into(),
            name: name.into(),
            numeric_id: None,
            sid: None,
            primary_group_id: None,
            domain: None,
            home: None,
            shell: None,
            enabled: None,
            members: Vec::new(),
        }
    }

    #[test]
    fn privileged_group_changes_are_high_severity() {
        assert_eq!(identity_severity(&snapshot("group", "sudo"), "changed"), Severity::High);
        assert_eq!(
            identity_severity(&snapshot("group", "Administrators"), "membership_changed"),
            Severity::High
        );
        assert_eq!(identity_severity(&snapshot("group", "users"), "changed"), Severity::Low);
    }

    #[test]
    fn identifies_membership_only_changes_and_deltas() {
        let mut previous = snapshot("group", "Administrators");
        previous.members = vec!["LAB\\alice".into(), "LAB\\may".into()];
        let mut current = previous.clone();
        current.members = vec!["LAB\\may".into(), "LAB\\zane".into()];

        assert!(only_members_changed(&previous, &current));
        let (added, removed) = membership_delta(&previous, &current);
        assert_eq!(added, vec!["LAB\\zane"]);
        assert_eq!(removed, vec!["LAB\\alice"]);
    }
}
