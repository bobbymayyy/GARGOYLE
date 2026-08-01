use crate::event::Severity;
use crate::util::read_string_limited_checked;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub agent: AgentConfig,
    pub collectors: CollectorsConfig,
    pub policy: PolicyConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub id: Option<String>,
    pub queue_capacity: usize,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorsConfig {
    pub process: ProcessCollectorConfig,
    pub network: NetworkCollectorConfig,
    pub filesystem: FilesystemCollectorConfig,
    pub identity: IdentityCollectorConfig,
    pub auth: AuthCollectorConfig,
    pub fingerprint: FingerprintConfig,
    pub kernel: KernelCollectorConfig,
    pub health: HealthCollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
    pub emit_stops: bool,
    pub capture_command_line: bool,
    pub max_command_line_bytes: usize,
    pub max_processes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
    pub emit_closed: bool,
    pub include_loopback: bool,
    pub correlate_processes: bool,
    pub fingerprint_processes: bool,
    pub max_sockets: usize,
    pub max_fds_per_process: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
    pub paths: Vec<PathBuf>,
    pub discover_home_ssh_keys: bool,
    pub home_roots: Vec<PathBuf>,
    pub max_depth: usize,
    pub max_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
    pub max_accounts: usize,
    pub linux_passwd_path: PathBuf,
    pub linux_group_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
    pub linux_log_paths: Vec<PathBuf>,
    pub max_read_bytes: usize,
    pub max_events_per_poll: usize,
    pub windows_event_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FingerprintConfig {
    pub enabled: bool,
    pub hash_executables: bool,
    pub windows_authenticode: bool,
    pub max_file_bytes: u64,
    pub max_cache_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KernelCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub emit_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthCollectorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    pub enabled: bool,
    pub collector: Option<String>,
    pub kind: Option<String>,
    pub path_prefix: Option<PathBuf>,
    pub process_name: Option<String>,
    pub process_sha256: Option<String>,
    pub process_signature_status: Option<String>,
    pub process_signer_thumbprint: Option<String>,
    pub auth_account: Option<String>,
    pub auth_outcome: Option<String>,
    pub auth_logon_type: Option<String>,
    pub identity_name: Option<String>,
    pub identity_operation: Option<String>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub action: RuleAction,
    pub severity: Option<Severity>,
    pub add_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Drop,
    SetSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    pub stdout: bool,
    pub file: Option<PathBuf>,
    pub unix_datagram: Option<PathBuf>,
    pub flush_each_event: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            collectors: CollectorsConfig::default(),
            policy: PolicyConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id: None,
            queue_capacity: 4096,
            labels: BTreeMap::new(),
        }
    }
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            process: ProcessCollectorConfig::default(),
            network: NetworkCollectorConfig::default(),
            filesystem: FilesystemCollectorConfig::default(),
            identity: IdentityCollectorConfig::default(),
            auth: AuthCollectorConfig::default(),
            fingerprint: FingerprintConfig::default(),
            kernel: KernelCollectorConfig::default(),
            health: HealthCollectorConfig::default(),
        }
    }
}

impl Default for ProcessCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 1000,
            emit_existing: false,
            emit_stops: true,
            capture_command_line: false,
            max_command_line_bytes: 4096,
            max_processes: 65_536,
        }
    }
}

impl Default for NetworkCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 2000,
            emit_existing: false,
            emit_closed: true,
            include_loopback: false,
            correlate_processes: true,
            fingerprint_processes: true,
            max_sockets: 262_144,
            max_fds_per_process: 65_536,
        }
    }
}

impl Default for FilesystemCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 3000,
            emit_existing: false,
            paths: default_sensitive_paths(),
            discover_home_ssh_keys: true,
            home_roots: default_home_roots(),
            max_depth: 4,
            max_files: 10_000,
        }
    }
}

impl Default for IdentityCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 5000,
            emit_existing: false,
            max_accounts: 10_000,
            linux_passwd_path: PathBuf::from("/etc/passwd"),
            linux_group_path: PathBuf::from("/etc/group"),
        }
    }
}

impl Default for AuthCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 2000,
            emit_existing: false,
            linux_log_paths: vec![
                PathBuf::from("/var/log/auth.log"),
                PathBuf::from("/var/log/secure"),
            ],
            max_read_bytes: 1024 * 1024,
            max_events_per_poll: 1024,
            windows_event_ids: vec![4624, 4625, 4648, 4672, 4688],
        }
    }
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hash_executables: true,
            windows_authenticode: cfg!(windows),
            max_file_bytes: 512 * 1024 * 1024,
            max_cache_entries: 4096,
        }
    }
}

impl Default for KernelCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(target_os = "linux"),
            interval_ms: 5000,
            emit_existing: false,
        }
    }
}

impl Default for HealthCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 60_000,
        }
    }
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            name: "unnamed".to_owned(),
            enabled: true,
            collector: None,
            kind: None,
            path_prefix: None,
            process_name: None,
            process_sha256: None,
            process_signature_status: None,
            process_signer_thumbprint: None,
            auth_account: None,
            auth_outcome: None,
            auth_logon_type: None,
            identity_name: None,
            identity_operation: None,
            local_port: None,
            remote_port: None,
            action: RuleAction::Allow,
            severity: None,
            add_labels: BTreeMap::new(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            stdout: true,
            file: None,
            unix_datagram: None,
            flush_each_event: true,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = read_string_limited_checked(path, 1024 * 1024)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let config = Self::default();
            config.validate()?;
            Ok(config)
        }
    }

    pub fn validate(&self) -> Result<()> {
        const MAX_QUEUE_CAPACITY: usize = 1_000_000;
        const MAX_COMMAND_LINE_BYTES: usize = 64 * 1024;
        const MAX_SNAPSHOT_ENTRIES: usize = 1_000_000;
        const MAX_FILES: usize = 1_000_000;
        const MAX_DEPTH: usize = 64;
        const MAX_FINGERPRINT_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
        const MAX_EVENTS_PER_POLL: usize = 100_000;
        const MAX_HOST_READ_BYTES: usize = 64 * 1024 * 1024;

        if self.agent.queue_capacity == 0 || self.agent.queue_capacity > MAX_QUEUE_CAPACITY {
            return Err(format!(
                "agent.queue_capacity must be between 1 and {MAX_QUEUE_CAPACITY}"
            )
            .into());
        }
        if self
            .agent
            .id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("agent.id may not be empty".into());
        }

        validate_interval("collectors.process.interval_ms", self.collectors.process.interval_ms)?;
        validate_interval("collectors.network.interval_ms", self.collectors.network.interval_ms)?;
        validate_interval(
            "collectors.filesystem.interval_ms",
            self.collectors.filesystem.interval_ms,
        )?;
        validate_interval(
            "collectors.identity.interval_ms",
            self.collectors.identity.interval_ms,
        )?;
        validate_interval("collectors.auth.interval_ms", self.collectors.auth.interval_ms)?;
        validate_interval("collectors.kernel.interval_ms", self.collectors.kernel.interval_ms)?;
        validate_interval("collectors.health.interval_ms", self.collectors.health.interval_ms)?;

        if self.collectors.process.max_command_line_bytes == 0
            || self.collectors.process.max_command_line_bytes > MAX_COMMAND_LINE_BYTES
        {
            return Err(format!(
                "collectors.process.max_command_line_bytes must be between 1 and {MAX_COMMAND_LINE_BYTES}"
            )
            .into());
        }
        if self.collectors.process.max_processes == 0
            || self.collectors.process.max_processes > MAX_SNAPSHOT_ENTRIES
        {
            return Err(format!(
                "collectors.process.max_processes must be between 1 and {MAX_SNAPSHOT_ENTRIES}"
            )
            .into());
        }
        if self.collectors.network.max_sockets == 0
            || self.collectors.network.max_sockets > MAX_SNAPSHOT_ENTRIES
        {
            return Err(format!(
                "collectors.network.max_sockets must be between 1 and {MAX_SNAPSHOT_ENTRIES}"
            )
            .into());
        }
        if self.collectors.network.max_fds_per_process == 0
            || self.collectors.network.max_fds_per_process > MAX_SNAPSHOT_ENTRIES
        {
            return Err(format!(
                "collectors.network.max_fds_per_process must be between 1 and {MAX_SNAPSHOT_ENTRIES}"
            )
            .into());
        }
        if self.collectors.filesystem.max_depth > MAX_DEPTH {
            return Err(format!(
                "collectors.filesystem.max_depth may not exceed {MAX_DEPTH}"
            )
            .into());
        }
        if self.collectors.filesystem.max_files == 0
            || self.collectors.filesystem.max_files > MAX_FILES
        {
            return Err(format!(
                "collectors.filesystem.max_files must be between 1 and {MAX_FILES}"
            )
            .into());
        }
        if self.collectors.identity.max_accounts == 0
            || self.collectors.identity.max_accounts > MAX_FILES
        {
            return Err(format!(
                "collectors.identity.max_accounts must be between 1 and {MAX_FILES}"
            )
            .into());
        }
        if self.collectors.auth.max_read_bytes == 0
            || self.collectors.auth.max_read_bytes > MAX_HOST_READ_BYTES
        {
            return Err(format!(
                "collectors.auth.max_read_bytes must be between 1 and {MAX_HOST_READ_BYTES}"
            )
            .into());
        }
        if self.collectors.auth.max_events_per_poll == 0
            || self.collectors.auth.max_events_per_poll > MAX_EVENTS_PER_POLL
        {
            return Err(format!(
                "collectors.auth.max_events_per_poll must be between 1 and {MAX_EVENTS_PER_POLL}"
            )
            .into());
        }
        if self.collectors.auth.windows_event_ids.is_empty() {
            return Err("collectors.auth.windows_event_ids may not be empty".into());
        }
        if self.collectors.auth.windows_event_ids.iter().any(|value| *value > 65_535) {
            return Err("collectors.auth.windows_event_ids values must fit in u16".into());
        }
        if self.collectors.fingerprint.max_file_bytes == 0
            || self.collectors.fingerprint.max_file_bytes > MAX_FINGERPRINT_FILE_BYTES
        {
            return Err(format!(
                "collectors.fingerprint.max_file_bytes must be between 1 and {MAX_FINGERPRINT_FILE_BYTES}"
            )
            .into());
        }
        if self.collectors.fingerprint.max_cache_entries == 0
            || self.collectors.fingerprint.max_cache_entries > MAX_SNAPSHOT_ENTRIES
        {
            return Err(format!(
                "collectors.fingerprint.max_cache_entries must be between 1 and {MAX_SNAPSHOT_ENTRIES}"
            )
            .into());
        }

        #[cfg(not(target_os = "linux"))]
        if self.collectors.kernel.enabled {
            return Err("collectors.kernel is only supported on Linux".into());
        }
        #[cfg(not(unix))]
        if self.output.unix_datagram.is_some() {
            return Err("output.unix_datagram is only supported on Unix".into());
        }

        if !self.output.stdout
            && self.output.file.is_none()
            && self.output.unix_datagram.is_none()
        {
            return Err("at least one output must be enabled".into());
        }
        for rule in &self.policy.rules {
            if rule.name.trim().is_empty() {
                return Err("policy rule names may not be empty".into());
            }
            if rule.action == RuleAction::SetSeverity && rule.severity.is_none() {
                return Err(format!("policy rule '{}' requires severity", rule.name).into());
            }
            if let Some(hash) = &rule.process_sha256 {
                let valid = hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
                if !valid {
                    return Err(format!(
                        "policy rule '{}' has an invalid process_sha256",
                        rule.name
                    )
                    .into());
                }
            }
            if let Some(thumbprint) = &rule.process_signer_thumbprint {
                let valid = thumbprint.len() == 40
                    && thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit());
                if !valid {
                    return Err(format!(
                        "policy rule '{}' has an invalid process_signer_thumbprint",
                        rule.name
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    pub fn to_pretty_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

fn validate_interval(name: &str, value: u64) -> Result<()> {
    if value < 100 {
        return Err(format!("{name} must be at least 100 milliseconds").into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_sensitive_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/group"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/gshadow"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/sudoers.d"),
        PathBuf::from("/etc/ssh"),
        PathBuf::from("/root/.ssh"),
    ]
}

#[cfg(windows)]
fn default_sensitive_paths() -> Vec<PathBuf> {
    let windows = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    vec![
        windows.join(r"System32\config\SAM"),
        windows.join(r"System32\config\SECURITY"),
        windows.join(r"System32\config\SYSTEM"),
        windows.join(r"System32\drivers\etc\hosts"),
        program_data.join(r"ssh\sshd_config"),
        program_data.join(r"ssh\administrators_authorized_keys"),
    ]
}

#[cfg(not(any(target_os = "linux", windows)))]
fn default_sensitive_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn default_home_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/home")]
}

#[cfg(windows)]
fn default_home_roots() -> Vec<PathBuf> {
    vec![PathBuf::from(r"C:\Users")]
}

#[cfg(not(any(target_os = "linux", windows)))]
fn default_home_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().expect("default config");
    }

    #[test]
    fn invalid_hash_rule_is_rejected() {
        let mut config = Config::default();
        config.policy.rules.push(RuleConfig {
            name: "bad-hash".into(),
            process_sha256: Some("nope".into()),
            ..RuleConfig::default()
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_signer_thumbprint_is_rejected() {
        let mut config = Config::default();
        config.policy.rules.push(RuleConfig {
            name: "bad-thumbprint".into(),
            process_signer_thumbprint: Some("not-a-thumbprint".into()),
            ..RuleConfig::default()
        });
        assert!(config.validate().is_err());
    }
}
