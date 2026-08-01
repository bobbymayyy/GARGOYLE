use crate::config::{PolicyConfig, RuleAction, RuleConfig};
use crate::event::Event;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<RuleConfig>,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            rules: config.rules,
        }
    }

    #[must_use]
    pub fn apply(&self, mut event: Event) -> Option<Event> {
        for rule in self.rules.iter().filter(|rule| rule.enabled) {
            if !matches_rule(rule, &event) {
                continue;
            }
            for (key, value) in &rule.add_labels {
                event.labels.insert(key.clone(), value.clone());
            }
            match rule.action {
                RuleAction::Allow => {}
                RuleAction::Drop => return None,
                RuleAction::SetSeverity => {
                    if let Some(severity) = rule.severity {
                        event.severity = severity;
                    }
                }
            }
        }
        Some(event)
    }
}

fn matches_rule(rule: &RuleConfig, event: &Event) -> bool {
    if rule
        .collector
        .as_deref()
        .is_some_and(|value| value != event.collector.as_str())
    {
        return false;
    }
    if rule
        .kind
        .as_deref()
        .is_some_and(|value| value != event.kind.as_str())
    {
        return false;
    }
    if let Some(prefix) = &rule.path_prefix {
        let Some(file) = &event.file else {
            return false;
        };
        if !Path::new(&file.path).starts_with(prefix) {
            return false;
        }
    }
    if let Some(expected) = &rule.process_name {
        let Some(process) = &event.process else {
            return false;
        };
        if process.name.as_deref() != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(expected) = &rule.process_sha256 {
        let actual = event
            .process
            .as_ref()
            .and_then(|process| process.fingerprint.as_ref())
            .and_then(|fingerprint| fingerprint.sha256.as_deref());
        if actual.is_none_or(|actual| !actual.eq_ignore_ascii_case(expected)) {
            return false;
        }
    }
    if let Some(expected) = &rule.process_signature_status {
        let actual = event
            .process
            .as_ref()
            .and_then(|process| process.fingerprint.as_ref())
            .and_then(|fingerprint| fingerprint.signature_status.as_deref());
        if actual.is_none_or(|actual| !actual.eq_ignore_ascii_case(expected)) {
            return false;
        }
    }
    if let Some(expected) = &rule.process_signer_thumbprint {
        let actual = event
            .process
            .as_ref()
            .and_then(|process| process.fingerprint.as_ref())
            .and_then(|fingerprint| fingerprint.signer_thumbprint.as_deref());
        if actual.is_none_or(|actual| !actual.eq_ignore_ascii_case(expected)) {
            return false;
        }
    }
    if let Some(expected) = &rule.auth_account {
        if event.auth.as_ref().and_then(|auth| auth.account.as_deref())
            != Some(expected.as_str())
        {
            return false;
        }
    }
    if let Some(expected) = &rule.auth_outcome {
        if event.auth.as_ref().map(|auth| auth.outcome.as_str()) != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(expected) = &rule.auth_logon_type {
        if event.auth.as_ref().and_then(|auth| auth.logon_type.as_deref())
            != Some(expected.as_str())
        {
            return false;
        }
    }
    if let Some(expected) = &rule.identity_name {
        if event.identity.as_ref().map(|identity| identity.name.as_str())
            != Some(expected.as_str())
        {
            return false;
        }
    }
    if let Some(expected) = &rule.identity_operation {
        if event.identity.as_ref().map(|identity| identity.operation.as_str())
            != Some(expected.as_str())
        {
            return false;
        }
    }
    if let Some(expected) = rule.local_port {
        if event.network.as_ref().map(|value| value.local_port) != Some(expected) {
            return false;
        }
    }
    if let Some(expected) = rule.remote_port {
        if event.network.as_ref().map(|value| value.remote_port) != Some(expected) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyConfig, RuleAction, RuleConfig};
    use crate::event::{AuthContext, EventFactory, NetworkContext, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn drops_matching_event() {
        let rule = RuleConfig {
            name: "drop-heartbeats".into(),
            kind: Some("agent.heartbeat".into()),
            action: RuleAction::Drop,
            ..RuleConfig::default()
        };
        let engine = PolicyEngine::new(PolicyConfig { rules: vec![rule] });
        let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
        let event = factory.event("health", "agent.heartbeat", Severity::Debug, "beat");
        assert!(engine.apply(event).is_none());
    }

    #[test]
    fn escalates_matching_event() {
        let rule = RuleConfig {
            name: "escalate-ssh".into(),
            kind: Some("network.listen".into()),
            local_port: Some(22),
            action: RuleAction::SetSeverity,
            severity: Some(Severity::High),
            ..RuleConfig::default()
        };
        let engine = PolicyEngine::new(PolicyConfig { rules: vec![rule] });
        let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
        let mut event = factory.event("network", "network.listen", Severity::Info, "ssh");
        event.network = Some(NetworkContext {
            protocol: "tcp".into(),
            local_address: "0.0.0.0".into(),
            local_port: 22,
            remote_address: "0.0.0.0".into(),
            remote_port: 0,
            state: "listen".into(),
            uid: Some(0),
            inode: Some(1),
            owning_pid: Some(42),
        });
        assert_eq!(engine.apply(event).expect("allowed").severity, Severity::High);
    }

    #[test]
    fn matches_normalized_logon_type() {
        let rule = RuleConfig {
            name: "rdp".into(),
            kind: Some("auth.login_success".into()),
            auth_logon_type: Some("remote_interactive".into()),
            action: RuleAction::SetSeverity,
            severity: Some(Severity::Medium),
            ..RuleConfig::default()
        };
        let engine = PolicyEngine::new(PolicyConfig { rules: vec![rule] });
        let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
        let mut event = factory.event("auth", "auth.login_success", Severity::Info, "rdp");
        event.auth = Some(AuthContext {
            outcome: "success".into(),
            mechanism: "windows_logon".into(),
            account: Some("may".into()),
            domain: Some("LAB".into()),
            logon_type: Some("remote_interactive".into()),
            source_address: None,
            source_port: None,
            workstation: None,
            authentication_package: None,
            logon_id: None,
            failure_reason: None,
            event_record_id: Some(1),
            privileges: Vec::new(),
        });
        assert_eq!(engine.apply(event).expect("allowed").severity, Severity::Medium);
    }
}
