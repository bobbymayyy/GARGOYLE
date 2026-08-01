use super::Collector;
use crate::config::FilesystemCollectorConfig;
use crate::event::{Event, EventFactory, FileContext, Severity};
use crate::metrics::Metrics;
use crate::Result;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct FilesystemCollector {
    config: FilesystemCollectorConfig,
    previous: HashMap<PathBuf, FileFingerprint>,
    initialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    size: u64,
    modified_nanos: Option<i128>,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    readonly: bool,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        let (mode, uid, gid) = unix_identity(metadata);
        Self {
            size: metadata.len(),
            modified_nanos: metadata.modified().ok().and_then(system_time_nanos),
            mode,
            uid,
            gid,
            readonly: metadata.permissions().readonly(),
        }
    }

    fn modified_at(&self) -> Option<DateTime<Utc>> {
        let nanos = self.modified_nanos?;
        if nanos < 0 {
            return None;
        }
        let seconds = nanos / 1_000_000_000;
        let subsecond = u32::try_from(nanos % 1_000_000_000).ok()?;
        DateTime::from_timestamp(i64::try_from(seconds).ok()?, subsecond)
    }
}

impl FilesystemCollector {
    #[must_use]
    pub fn new(config: FilesystemCollectorConfig) -> Self {
        Self {
            config,
            previous: HashMap::new(),
            initialized: false,
        }
    }

    fn snapshot(&self) -> Result<HashMap<PathBuf, FileFingerprint>> {
        let mut snapshot = HashMap::new();
        let mut visited = HashSet::new();
        let mut paths = self.config.paths.clone();
        if self.config.discover_home_ssh_keys {
            paths.extend(discover_home_ssh_paths(
                &self.config.home_roots,
                self.config.max_files,
            )?);
        }
        for path in paths {
            self.walk(&path, 0, &mut snapshot, &mut visited)?;
        }
        Ok(snapshot)
    }

    fn walk(
        &self,
        path: &Path,
        depth: usize,
        snapshot: &mut HashMap<PathBuf, FileFingerprint>,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        if depth > self.config.max_depth {
            return Ok(());
        }
        let normalized = path.to_path_buf();
        if visited.len() >= self.config.max_files {
            return Err(format!(
                "filesystem traversal exceeded configured max_files entry ceiling ({})",
                self.config.max_files
            )
            .into());
        }
        if !visited.insert(normalized.clone()) {
            return Ok(());
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if metadata.is_dir() {
            let entries = fs::read_dir(path)?;
            for entry in entries {
                self.walk(&entry?.path(), depth + 1, snapshot, visited)?;
            }
            return Ok(());
        }
        if snapshot.len() >= self.config.max_files {
            return Err(format!(
                "filesystem snapshot exceeded configured max_files ({})",
                self.config.max_files
            )
            .into());
        }
        snapshot.insert(normalized, FileFingerprint::from_metadata(&metadata));
        Ok(())
    }

    fn make_event(
        &self,
        factory: &EventFactory,
        path: &Path,
        operation: &str,
        fingerprint: Option<&FileFingerprint>,
    ) -> Event {
        let (kind, severity) = classify(path, operation);
        let mut event = factory.event(
            self.name(),
            kind,
            severity,
            format!("{}: {}", operation, path.display()),
        );
        event.file = Some(FileContext {
            path: path.to_string_lossy().into_owned(),
            operation: operation.to_owned(),
            size: fingerprint.map(|value| value.size),
            modified_at: fingerprint.and_then(FileFingerprint::modified_at),
            mode: fingerprint.and_then(|value| value.mode),
            uid: fingerprint.and_then(|value| value.uid),
            gid: fingerprint.and_then(|value| value.gid),
            readonly: fingerprint.map(|value| value.readonly),
        });
        event
    }
}

impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn interval(&self) -> Duration {
        Duration::from_millis(self.config.interval_ms)
    }

    fn collect(&mut self, factory: &EventFactory, _metrics: &Metrics) -> Result<Vec<Event>> {
        let current = self.snapshot()?;
        let mut events = Vec::new();
        if !self.initialized {
            if self.config.emit_existing {
                for (path, fingerprint) in &current {
                    events.push(self.make_event(factory, path, "observed", Some(fingerprint)));
                }
            }
        } else {
            for (path, fingerprint) in &current {
                match self.previous.get(path) {
                    None => events.push(self.make_event(factory, path, "created", Some(fingerprint))),
                    Some(previous) if previous != fingerprint => {
                        events.push(self.make_event(factory, path, "modified", Some(fingerprint)));
                    }
                    Some(_) => {}
                }
            }
            for (path, fingerprint) in &self.previous {
                if !current.contains_key(path) {
                    events.push(self.make_event(factory, path, "deleted", Some(fingerprint)));
                }
            }
        }
        self.previous = current;
        self.initialized = true;
        Ok(events)
    }
}

fn discover_home_ssh_paths(home_roots: &[PathBuf], max_paths: usize) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for root in home_roots {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            if paths.len() >= max_paths {
                return Err(format!(
                    "home-directory discovery exceeded configured max_files entry ceiling ({max_paths})"
                )
                .into());
            }
            paths.push(entry?.path().join(".ssh"));
        }
    }
    Ok(paths)
}

fn classify(path: &Path, operation: &str) -> (&'static str, Severity) {
    let value = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if value.ends_with("/etc/shadow") || value.ends_with("/etc/gshadow") {
        return ("identity.credential_database_changed", Severity::Critical);
    }
    if value.ends_with("/etc/passwd") || value.ends_with("/etc/group") {
        return ("identity.database_changed", Severity::High);
    }
    if value.ends_with("/etc/sudoers") || value.contains("/etc/sudoers.d/") {
        return ("auth.sudoers_changed", Severity::High);
    }
    if value.contains("/etc/ssh/") || value.ends_with("/programdata/ssh/sshd_config") {
        return ("auth.ssh_config_changed", Severity::High);
    }
    if value.contains("/.ssh/") || value.ends_with("administrators_authorized_keys") {
        return ("auth.ssh_artifact_changed", Severity::High);
    }
    if value.ends_with("/windows/system32/config/sam")
        || value.ends_with("/windows/system32/config/security")
        || value.ends_with("/windows/system32/config/system")
    {
        return ("identity.credential_database_changed", Severity::Critical);
    }
    if value.ends_with("/windows/system32/drivers/etc/hosts") {
        return ("network.hosts_file_changed", Severity::High);
    }
    match operation {
        "created" => ("file.created", Severity::Medium),
        "deleted" => ("file.deleted", Severity::Medium),
        "modified" => ("file.modified", Severity::Medium),
        _ => ("file.observed", Severity::Info),
    }
}

fn system_time_nanos(value: SystemTime) -> Option<i128> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok(),
        Err(error) => i128::try_from(error.duration().as_nanos()).ok().map(|value| -value),
    }
}

#[cfg(unix)]
fn unix_identity(metadata: &Metadata) -> (Option<u32>, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    (Some(metadata.mode()), Some(metadata.uid()), Some(metadata.gid()))
}

#[cfg(not(unix))]
fn unix_identity(_metadata: &Metadata) -> (Option<u32>, Option<u32>, Option<u32>) {
    (None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_sensitive_paths_on_both_platforms() {
        assert_eq!(classify(Path::new("/etc/shadow"), "modified").1, Severity::Critical);
        assert_eq!(
            classify(Path::new("/home/may/.ssh/authorized_keys"), "modified").0,
            "auth.ssh_artifact_changed"
        );
        assert_eq!(
            classify(Path::new(r"C:\Windows\System32\config\SAM"), "modified").0,
            "identity.credential_database_changed"
        );
        assert_eq!(
            classify(Path::new(r"C:\Windows\System32\drivers\etc\hosts"), "modified").0,
            "network.hosts_file_changed"
        );
    }

    #[test]
    fn refuses_partial_snapshot_at_file_ceiling() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::write(directory.path().join("one"), b"1").expect("fixture");
        fs::write(directory.path().join("two"), b"2").expect("fixture");
        let mut config = FilesystemCollectorConfig::default();
        config.paths = vec![directory.path().to_path_buf()];
        config.discover_home_ssh_keys = false;
        config.max_files = 1;
        let collector = FilesystemCollector::new(config);
        assert!(collector.snapshot().is_err());
    }
}
