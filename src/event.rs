use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub const EVENT_SCHEMA_VERSION: &str = "gargoyle.event/v2";

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub id: String,
    pub hostname: String,
    pub version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageFingerprint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessContext {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<ImageFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkContext {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owning_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileContext {
    pub path: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityContext {
    pub object_type: String,
    pub operation: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_group_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockdown: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthContext {
    pub outcome: String,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workstation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_record_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privileges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub agent: AgentIdentity,
    pub collector: String,
    pub kind: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<KernelContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthContext>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

#[derive(Debug)]
pub struct EventFactory {
    identity: AgentIdentity,
    labels: BTreeMap<String, String>,
    sequence: AtomicU64,
}

impl EventFactory {
    #[must_use]
    pub fn new(id: String, hostname: String, labels: BTreeMap<String, String>) -> Self {
        Self {
            identity: AgentIdentity {
                id,
                hostname,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
            },
            labels,
            sequence: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn event(
        &self,
        collector: impl Into<String>,
        kind: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Event {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let timestamp = Utc::now();
        let nanos = timestamp.timestamp_nanos_opt().unwrap_or_default();
        Event {
            schema_version: EVENT_SCHEMA_VERSION.to_owned(),
            event_id: format!("{}-{nanos}-{sequence}", self.identity.id),
            sequence,
            timestamp,
            agent: self.identity.clone(),
            collector: collector.into(),
            kind: kind.into(),
            severity,
            message: message.into(),
            process: None,
            network: None,
            file: None,
            identity: None,
            kernel: None,
            auth: None,
            labels: self.labels.clone(),
            data: Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_sequences_are_monotonic() {
        let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
        let first = factory.event("test", "one", Severity::Info, "one");
        let second = factory.event("test", "two", Severity::Info, "two");
        assert_eq!(first.sequence + 1, second.sequence);
        assert_ne!(first.event_id, second.event_id);
        assert_eq!(first.schema_version, "gargoyle.event/v2");
    }
}
