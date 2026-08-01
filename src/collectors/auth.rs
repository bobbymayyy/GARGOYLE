#[cfg(target_os = "linux")]
mod implementation {
    use super::super::Collector;
    use crate::config::{AuthCollectorConfig, FingerprintConfig, ProcessCollectorConfig};
    use crate::event::{AuthContext, Event, EventFactory, Severity};
    use crate::metrics::Metrics;
    use crate::Result;
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[derive(Debug)]
    pub struct AuthCollector {
        config: AuthCollectorConfig,
        capture_command_line: bool,
        max_command_line_bytes: usize,
        cursors: HashMap<PathBuf, LogCursor>,
    }

    #[derive(Debug, Default)]
    struct LogCursor {
        device: u64,
        inode: u64,
        offset: u64,
        carry: String,
        initialized: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ParsedAuth {
        kind: &'static str,
        severity: Severity,
        outcome: &'static str,
        mechanism: &'static str,
        account: Option<String>,
        source_address: Option<String>,
        source_port: Option<u16>,
        message: String,
        details: serde_json::Value,
    }

    impl AuthCollector {
        #[must_use]
        pub fn new(
            config: AuthCollectorConfig,
            _fingerprint: FingerprintConfig,
            process: ProcessCollectorConfig,
        ) -> Self {
            Self {
                config,
                capture_command_line: process.capture_command_line,
                max_command_line_bytes: process.max_command_line_bytes,
                cursors: HashMap::new(),
            }
        }

        fn collect_path(
            &mut self,
            path: &Path,
            factory: &EventFactory,
            event_limit: usize,
        ) -> Result<Vec<Event>> {
            let metadata = match fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) => return Err(error.into()),
            };
            let cursor = self.cursors.entry(path.to_path_buf()).or_default();
            initialize_or_rotate(cursor, &metadata, self.config.emit_existing);
            if cursor.offset >= metadata.len() {
                return Ok(Vec::new());
            }

            let start_offset = cursor.offset;
            let original_carry = cursor.carry.clone();
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(start_offset))?;
            let mut bytes = Vec::with_capacity(self.config.max_read_bytes.min(64 * 1024));
            file.take(self.config.max_read_bytes as u64)
                .read_to_end(&mut bytes)?;
            cursor.offset = cursor.offset.saturating_add(bytes.len() as u64);

            let mut text = std::mem::take(&mut cursor.carry);
            text.push_str(&String::from_utf8_lossy(&bytes));
            let ends_with_newline = text.ends_with('\n');
            let mut lines = text.split('\n').map(str::trim_end).collect::<Vec<_>>();
            if !ends_with_newline {
                cursor.carry = lines.pop().unwrap_or_default().to_owned();
                if cursor.carry.len() > self.config.max_read_bytes {
                    cursor.carry.clear();
                }
            }
            let mut events = Vec::new();
            for line in lines {
                let Some(parsed) = parse_auth_line(
                    line,
                    self.capture_command_line,
                    self.max_command_line_bytes,
                ) else {
                    continue;
                };
                if events.len() >= event_limit {
                    cursor.offset = start_offset;
                    cursor.carry = original_carry;
                    return Err(format!(
                        "authentication event burst exceeded remaining per-poll limit ({event_limit}) for {}",
                        path.display()
                    )
                    .into());
                }
                let mut event = factory.event("auth", parsed.kind, parsed.severity, parsed.message);
                event.auth = Some(AuthContext {
                    outcome: parsed.outcome.to_owned(),
                    mechanism: parsed.mechanism.to_owned(),
                    account: parsed.account,
                    domain: None,
                    logon_type: None,
                    source_address: parsed.source_address,
                    source_port: parsed.source_port,
                    workstation: None,
                    authentication_package: None,
                    logon_id: None,
                    failure_reason: None,
                    event_record_id: None,
                    privileges: Vec::new(),
                });
                event.data = json!({
                    "source": path.to_string_lossy(),
                    "details": parsed.details,
                });
                events.push(event);
            }
            Ok(events)
        }
    }

    impl Collector for AuthCollector {
        fn name(&self) -> &'static str {
            "auth"
        }

        fn interval(&self) -> Duration {
            Duration::from_millis(self.config.interval_ms)
        }

        fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
            let mut events = Vec::new();
            for path in self.config.linux_log_paths.clone() {
                let remaining = self.config.max_events_per_poll.saturating_sub(events.len());
                if remaining == 0 {
                    break;
                }
                let path_events = self.collect_path(&path, factory, remaining)?;
                events.extend(path_events);
            }
            Ok(events)
        }
    }

    fn initialize_or_rotate(cursor: &mut LogCursor, metadata: &Metadata, emit_existing: bool) {
        let identity_changed = cursor.initialized
            && (cursor.device != metadata.dev() || cursor.inode != metadata.ino());
        let truncated = cursor.initialized && metadata.len() < cursor.offset;
        if !cursor.initialized || identity_changed || truncated {
            cursor.device = metadata.dev();
            cursor.inode = metadata.ino();
            cursor.carry.clear();
            cursor.offset = if !cursor.initialized && !emit_existing {
                metadata.len()
            } else {
                0
            };
            cursor.initialized = true;
        }
    }

    fn parse_auth_line(
        line: &str,
        capture_command_line: bool,
        max_command_line_bytes: usize,
    ) -> Option<ParsedAuth> {
        if line.contains("sshd") && line.contains("Accepted ") {
            return parse_ssh(line, true);
        }
        if line.contains("sshd") && line.contains("Failed ") {
            return parse_ssh(line, false);
        }
        if line.contains("sudo:") && line.contains("authentication failure") {
            let account = field_after(line, "user=").or_else(|| field_after(line, "ruser="));
            return Some(ParsedAuth {
                kind: "auth.privilege_failure",
                severity: Severity::High,
                outcome: "failure",
                mechanism: "sudo",
                message: format!(
                    "sudo authentication failed{}",
                    account
                        .as_deref()
                        .map_or_else(String::new, |value| format!(" for {value}"))
                ),
                account,
                source_address: None,
                source_port: None,
                details: json!({ "raw": bounded_raw(line) }),
            });
        }
        if line.contains("sudo:") && line.contains("COMMAND=") {
            let account = sudo_actor(line);
            let command = line
                .split_once("COMMAND=")
                .map(|(_, value)| bounded_text(value.trim(), max_command_line_bytes));
            let target = field_after(line, "USER=");
            let details = if capture_command_line {
                json!({ "target_account": target.clone(), "command": command })
            } else {
                json!({ "target_account": target.clone() })
            };
            return Some(ParsedAuth {
                kind: "auth.privilege_use",
                severity: Severity::Medium,
                outcome: "success",
                mechanism: "sudo",
                message: format!(
                    "sudo command by {} as {}",
                    account.as_deref().unwrap_or("unknown"),
                    target.as_deref().unwrap_or("unknown")
                ),
                account,
                source_address: None,
                source_port: None,
                details,
            });
        }
        if line.contains("su:")
            && (line.contains("FAILED SU") || line.contains("authentication failure"))
        {
            let account = field_after(line, "user=");
            return Some(ParsedAuth {
                kind: "auth.privilege_failure",
                severity: Severity::High,
                outcome: "failure",
                mechanism: "su",
                message: "su authentication failed".to_owned(),
                account,
                source_address: None,
                source_port: None,
                details: json!({ "raw": bounded_raw(line) }),
            });
        }
        None
    }

    fn parse_ssh(line: &str, success: bool) -> Option<ParsedAuth> {
        let marker = if success { "Accepted " } else { "Failed " };
        let tail = line.split_once(marker)?.1;
        let (method, after_method) = tail.split_once(" for ")?;
        let after_method = after_method.strip_prefix("invalid user ").unwrap_or(after_method);
        let (account, source) = after_method.split_once(" from ")?;
        let source_fields = source.split_whitespace().collect::<Vec<_>>();
        let source_address = source_fields.first().map(|value| (*value).to_owned());
        let source_port = source_fields
            .windows(2)
            .find_map(|pair| (pair[0] == "port").then_some(pair[1]))
            .and_then(|value| value.parse().ok());
        let kind = if success {
            "auth.login_success"
        } else {
            "auth.login_failure"
        };
        Some(ParsedAuth {
            kind,
            severity: if success { Severity::Info } else { Severity::High },
            outcome: if success { "success" } else { "failure" },
            mechanism: "ssh",
            account: Some(account.trim().to_owned()),
            source_address,
            source_port,
            message: format!(
                "SSH {} for {} using {}",
                if success { "login accepted" } else { "login failed" },
                account.trim(),
                method.trim()
            ),
            details: json!({ "authentication_method": method.trim() }),
        })
    }

    fn field_after(line: &str, marker: &str) -> Option<String> {
        line.split_once(marker)?
            .1
            .split(|character: char| character.is_whitespace() || character == ';')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }

    fn sudo_actor(line: &str) -> Option<String> {
        let tail = line.split_once("sudo:")?.1.trim_start();
        tail.split_once(':')
            .or_else(|| tail.split_once(' '))
            .map(|(account, _)| account.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    fn bounded_raw(line: &str) -> String {
        line.chars().take(4096).collect()
    }

    fn bounded_text(value: &str, max_bytes: usize) -> String {
        if value.len() <= max_bytes {
            return value.to_owned();
        }
        let mut boundary = max_bytes;
        while boundary > 0 && !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value[..boundary].to_owned()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_successful_ssh_login() {
            let parsed = parse_auth_line(
                "Jul 31 host sshd[42]: Accepted publickey for may from 192.0.2.10 port 55221 ssh2",
                false,
                4096,
            )
            .expect("auth event");
            assert_eq!(parsed.kind, "auth.login_success");
            assert_eq!(parsed.account.as_deref(), Some("may"));
            assert_eq!(parsed.source_address.as_deref(), Some("192.0.2.10"));
            assert_eq!(parsed.source_port, Some(55221));
        }

        #[test]
        fn parses_failed_invalid_user_login() {
            let parsed = parse_auth_line(
                "Jul 31 host sshd[42]: Failed password for invalid user ghost from 198.51.100.4 port 22 ssh2",
                false,
                4096,
            )
            .expect("auth event");
            assert_eq!(parsed.kind, "auth.login_failure");
            assert_eq!(parsed.account.as_deref(), Some("ghost"));
        }

        #[test]
        fn parses_sudo_command() {
            let parsed = parse_auth_line(
                "Jul 31 host sudo: may : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id",
                true,
                4096,
            )
            .expect("auth event");
            assert_eq!(parsed.kind, "auth.privilege_use");
            assert_eq!(parsed.account.as_deref(), Some("may"));
            assert_eq!(parsed.details["target_account"], "root");
            assert_eq!(parsed.details["command"], "/usr/bin/id");
        }

        #[test]
        fn redacts_sudo_command_when_command_line_capture_is_disabled() {
            let parsed = parse_auth_line(
                "Jul 31 host sudo: may : USER=root ; COMMAND=/usr/bin/id --token secret",
                false,
                4096,
            )
            .expect("auth event");
            assert!(parsed.details.get("command").is_none());
        }

        #[test]
        fn burst_limit_rewinds_log_cursor() {
            use std::collections::BTreeMap;

            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory.path().join("auth.log");
            fs::write(
                &path,
                concat!(
                    "Jul 31 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n",
                    "Jul 31 host sshd[2]: Failed password for root from 192.0.2.2 port 23 ssh2\n",
                ),
            )
            .expect("fixture");

            let mut config = AuthCollectorConfig::default();
            config.emit_existing = true;
            config.linux_log_paths = vec![path];
            config.max_events_per_poll = 1;
            let mut collector = AuthCollector::new(
                config,
                FingerprintConfig::default(),
                ProcessCollectorConfig::default(),
            );
            let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
            let metrics = Metrics::default();
            assert!(collector.collect(&factory, &metrics).is_err());

            collector.config.max_events_per_poll = 2;
            let events = collector.collect(&factory, &metrics).expect("replayed events");
            assert_eq!(events.len(), 2);
        }
    }
}

#[cfg(windows)]
mod implementation {
    use super::super::Collector;
    use crate::config::{AuthCollectorConfig, FingerprintConfig, ProcessCollectorConfig};
    use crate::event::{AuthContext, Event, EventFactory, ProcessContext, Severity};
    use crate::fingerprint::ExecutableFingerprinter;
    use crate::metrics::Metrics;
    use crate::platform::run_powershell_json;
    use crate::Result;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[derive(Debug)]
    pub struct AuthCollector {
        config: AuthCollectorConfig,
        last_record_id: Option<u64>,
        fingerprinter: ExecutableFingerprinter,
        process_config: ProcessCollectorConfig,
    }

    #[derive(Debug, Deserialize)]
    struct WindowsEvent {
        record_id: u64,
        event_id: u32,
        #[serde(default)]
        time_created: Option<String>,
        #[serde(default)]
        data: BTreeMap<String, String>,
    }

    impl AuthCollector {
        #[must_use]
        pub fn new(
            config: AuthCollectorConfig,
            fingerprint: FingerprintConfig,
            process_config: ProcessCollectorConfig,
        ) -> Self {
            Self {
                config,
                last_record_id: None,
                fingerprinter: ExecutableFingerprinter::new(fingerprint),
                process_config,
            }
        }

        fn initialize_cursor(&mut self) -> Result<()> {
            if self.last_record_id.is_some() || self.config.emit_existing {
                return Ok(());
            }
            let ids = powershell_ids(&self.config.windows_event_ids);
            let script = format!(
                r#"$ids = @({ids})
$winEventErrors = @()
$event = Get-WinEvent -FilterHashtable @{{ LogName = 'Security'; Id = $ids }} -MaxEvents 1 -ErrorAction SilentlyContinue -ErrorVariable +winEventErrors
$fatal = @($winEventErrors | Where-Object {{ $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }})
if ($fatal.Count -gt 0) {{ throw [string]$fatal[0] }}
if ($event) {{ [pscustomobject]@{{ record_id = [uint64]$event.RecordId }} | ConvertTo-Json -Compress }} else {{ 'null' }}"#
            );
            let value = run_powershell_json(&script)?;
            self.last_record_id = value
                .get("record_id")
                .and_then(Value::as_u64)
                .or(Some(0));
            Ok(())
        }

        fn query(&self) -> Result<Vec<WindowsEvent>> {
            let ids = powershell_ids(&self.config.windows_event_ids);
            let predicate = self
                .config
                .windows_event_ids
                .iter()
                .map(|id| format!("EventID={id}"))
                .collect::<Vec<_>>()
                .join(" or ");
            let after = self.last_record_id.unwrap_or(0);
            let script = format!(
                r#"$ErrorActionPreference = 'Stop'
$ids = @({ids})
$after = [uint64]{after}
$cursorErrors = @()
$latest = Get-WinEvent -FilterHashtable @{{ LogName = 'Security'; Id = $ids }} -MaxEvents 1 -ErrorAction SilentlyContinue -ErrorVariable +cursorErrors
$cursorFatal = @($cursorErrors | Where-Object {{ $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }})
if ($cursorFatal.Count -gt 0) {{ throw [string]$cursorFatal[0] }}
if ($latest -and [uint64]$latest.RecordId -lt $after) {{ $after = [uint64]0 }}
$query = "*[System[(EventRecordID > $after) and ({predicate})]]"
$winEventErrors = @()
$events = @(Get-WinEvent -LogName Security -FilterXPath $query -Oldest -MaxEvents {limit} -ErrorAction SilentlyContinue -ErrorVariable +winEventErrors)
$fatal = @($winEventErrors | Where-Object {{ $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }})
if ($fatal.Count -gt 0) {{ throw [string]$fatal[0] }}
$items = @($events | ForEach-Object {{
    [xml]$xml = $_.ToXml()
    $fields = [ordered]@{{}}
    foreach ($node in @($xml.Event.EventData.Data)) {{
        if ($node.Name) {{ $fields[[string]$node.Name] = [string]$node.'#text' }}
    }}
    [pscustomobject]@{{
        record_id = [uint64]$_.RecordId
        event_id = [uint32]$_.Id
        time_created = if ($_.TimeCreated) {{ $_.TimeCreated.ToUniversalTime().ToString('o') }} else {{ $null }}
        data = $fields
    }}
}})
ConvertTo-Json -InputObject @($items) -Compress -Depth 6"#,
                limit = self.config.max_events_per_poll,
            );
            let value = run_powershell_json(&script)?;
            match value {
                Value::Array(_) => Ok(serde_json::from_value(value)?),
                Value::Null => Ok(Vec::new()),
                other => Ok(vec![serde_json::from_value(other)?]),
            }
        }

        fn convert(&mut self, source: WindowsEvent, factory: &EventFactory) -> Option<Event> {
            match source.event_id {
                4624 => Some(auth_event(
                    factory,
                    &source,
                    "auth.login_success",
                    Severity::Info,
                    "success",
                    "windows_logon",
                )),
                4625 => Some(auth_event(
                    factory,
                    &source,
                    "auth.login_failure",
                    Severity::High,
                    "failure",
                    "windows_logon",
                )),
                4648 => Some(auth_event(
                    factory,
                    &source,
                    "auth.explicit_credentials",
                    Severity::Medium,
                    "unknown",
                    "windows_explicit_credentials",
                )),
                4672 => Some(auth_event(
                    factory,
                    &source,
                    "auth.privileged_logon",
                    Severity::Low,
                    "success",
                    "windows_special_logon",
                )),
                4688 => Some(self.process_event(source, factory)),
                _ => None,
            }
        }

        fn process_event(&mut self, source: WindowsEvent, factory: &EventFactory) -> Event {
            let executable = value(&source.data, &["NewProcessName"]);
            let pid = value(&source.data, &["NewProcessId"])
                .and_then(|value| parse_windows_integer(&value))
                .unwrap_or(0);
            let ppid = value(&source.data, &["ProcessId", "CreatorProcessId"])
                .and_then(|value| parse_windows_integer(&value));
            let username = qualified_account(&source.data);
            let fingerprint = self.fingerprinter.fingerprint(executable.as_deref());
            let mut event = factory.event(
                "auth",
                "process.audit_start",
                Severity::Info,
                format!(
                    "Windows audited process start: {} (pid {pid})",
                    executable.as_deref().unwrap_or("unknown")
                ),
            );
            event.process = Some(ProcessContext {
                pid,
                ppid,
                uid: None,
                gid: None,
                username,
                session_id: None,
                name: executable
                    .as_deref()
                    .and_then(|path| std::path::Path::new(path).file_name())
                    .map(|name| name.to_string_lossy().into_owned()),
                executable,
                command_line: if self.process_config.capture_command_line {
                    value(&source.data, &["CommandLine"]).map(|value| {
                        bounded_text(&value, self.process_config.max_command_line_bytes)
                    })
                } else {
                    None
                },
                cgroup: None,
                start_key: Some(format!("event-record:{}", source.record_id)),
                fingerprint,
            });
            event.data = json!({
                "windows_event_id": source.event_id,
                "event_record_id": source.record_id,
                "source_time": source.time_created,
                "token_elevation_type": value(&source.data, &["TokenElevationType"]),
                "mandatory_label": value(&source.data, &["MandatoryLabel"]),
            });
            event
        }
    }

    impl Collector for AuthCollector {
        fn name(&self) -> &'static str {
            "auth"
        }

        fn interval(&self) -> Duration {
            Duration::from_millis(self.config.interval_ms)
        }

        fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
            self.initialize_cursor()?;
            let sources = self.query()?;
            let mut events = Vec::new();
            for source in sources {
                self.last_record_id = Some(
                    self.last_record_id
                        .unwrap_or(0)
                        .max(source.record_id),
                );
                if let Some(event) = self.convert(source, factory) {
                    events.push(event);
                }
            }
            Ok(events)
        }
    }

    fn auth_event(
        factory: &EventFactory,
        source: &WindowsEvent,
        kind: &str,
        severity: Severity,
        outcome: &str,
        mechanism: &str,
    ) -> Event {
        let account = value(
            &source.data,
            &["TargetUserName", "SubjectUserName", "AccountName"],
        );
        let domain = value(
            &source.data,
            &["TargetDomainName", "SubjectDomainName", "AccountDomain"],
        );
        let message = format!(
            "Windows security event {}: {}{}",
            source.event_id,
            kind,
            account
                .as_deref()
                .map_or_else(String::new, |value| format!(" for {value}"))
        );
        let mut privileges = value(&source.data, &["PrivilegeList"])
            .map(|value| value.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_default();
        privileges.sort_unstable();
        privileges.dedup();
        let mut event = factory.event("auth", kind, severity, message);
        event.auth = Some(AuthContext {
            outcome: outcome.to_owned(),
            mechanism: mechanism.to_owned(),
            account,
            domain,
            logon_type: value(&source.data, &["LogonType"]).map(|value| logon_type(&value)),
            source_address: value(&source.data, &["IpAddress", "NetworkAddress"]),
            source_port: value(&source.data, &["IpPort"]).and_then(|value| value.parse().ok()),
            workstation: value(&source.data, &["WorkstationName"]),
            authentication_package: value(
                &source.data,
                &["AuthenticationPackageName", "LogonProcessName"],
            ),
            logon_id: value(&source.data, &["TargetLogonId", "SubjectLogonId"]),
            failure_reason: value(&source.data, &["FailureReason", "Status", "SubStatus"]),
            event_record_id: Some(source.record_id),
            privileges,
        });
        event.data = json!({
            "windows_event_id": source.event_id,
            "source_time": source.time_created.clone(),
            "process_name": value(&source.data, &["ProcessName"]),
            "target_server": value(&source.data, &["TargetServerName"]),
        });
        event
    }

    fn value(data: &BTreeMap<String, String>, names: &[&str]) -> Option<String> {
        names
            .iter()
            .find_map(|name| data.get(*name))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty() && *value != "-")
            .map(str::to_owned)
    }

    fn qualified_account(data: &BTreeMap<String, String>) -> Option<String> {
        let account = value(data, &["SubjectUserName", "TargetUserName"])?;
        let domain = value(data, &["SubjectDomainName", "TargetDomainName"]);
        Some(match domain {
            Some(domain) => format!("{domain}\\{account}"),
            None => account,
        })
    }

    fn parse_windows_integer(value: &str) -> Option<u32> {
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse().ok(), |hex| u32::from_str_radix(hex, 16).ok())
    }

    fn logon_type(value: &str) -> String {
        match value {
            "2" => "interactive",
            "3" => "network",
            "4" => "batch",
            "5" => "service",
            "7" => "unlock",
            "8" => "network_cleartext",
            "9" => "new_credentials",
            "10" => "remote_interactive",
            "11" => "cached_interactive",
            "12" => "cached_remote_interactive",
            "13" => "cached_unlock",
            other => other,
        }
        .to_owned()
    }

    fn bounded_text(value: &str, max_bytes: usize) -> String {
        if value.len() <= max_bytes {
            return value.to_owned();
        }
        let mut boundary = max_bytes;
        while boundary > 0 && !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value[..boundary].to_owned()
    }

    fn powershell_ids(ids: &[u32]) -> String {
        ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod implementation {
    use super::super::Collector;
    use crate::config::{AuthCollectorConfig, FingerprintConfig, ProcessCollectorConfig};
    use crate::event::{Event, EventFactory};
    use crate::metrics::Metrics;
    use crate::Result;
    use std::time::Duration;

    #[derive(Debug)]
    pub struct AuthCollector {
        config: AuthCollectorConfig,
    }

    impl AuthCollector {
        #[must_use]
        pub fn new(
            config: AuthCollectorConfig,
            _fingerprint: FingerprintConfig,
            _process: ProcessCollectorConfig,
        ) -> Self {
            Self { config }
        }
    }

    impl Collector for AuthCollector {
        fn name(&self) -> &'static str {
            "auth"
        }

        fn interval(&self) -> Duration {
            Duration::from_millis(self.config.interval_ms)
        }

        fn collect(&mut self, _factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
            Err("authentication collection is unsupported on this platform".into())
        }
    }
}

pub use implementation::AuthCollector;
