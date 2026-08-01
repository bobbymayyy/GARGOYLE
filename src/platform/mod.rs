#[cfg(not(any(target_os = "linux", windows)))]
use crate::config::{IdentityCollectorConfig, NetworkCollectorConfig, ProcessCollectorConfig};
#[cfg(not(any(target_os = "linux", windows)))]
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub start_key: String,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub username: Option<String>,
    pub session_id: Option<u32>,
    pub name: Option<String>,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub cgroup: Option<String>,
}

impl ProcessSnapshot {
    #[must_use]
    pub fn to_context(
        &self,
        fingerprint: Option<crate::event::ImageFingerprint>,
    ) -> crate::event::ProcessContext {
        crate::event::ProcessContext {
            pid: self.pid,
            ppid: self.ppid,
            uid: self.uid,
            gid: self.gid,
            username: self.username.clone(),
            session_id: self.session_id,
            name: self.name.clone(),
            executable: self.executable.clone(),
            command_line: self.command_line.clone(),
            cgroup: self.cgroup.clone(),
            start_key: Some(self.start_key.clone()),
            fingerprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentitySnapshot {
    pub object_type: String,
    pub name: String,
    pub numeric_id: Option<u32>,
    pub sid: Option<String>,
    pub primary_group_id: Option<u32>,
    pub domain: Option<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub enabled: Option<bool>,
    pub members: Vec<String>,
}

impl IdentitySnapshot {
    #[must_use]
    pub fn key(&self) -> (String, String) {
        (self.object_type.clone(), self.name.clone())
    }

    #[must_use]
    pub fn to_context(&self, operation: impl Into<String>) -> crate::event::IdentityContext {
        crate::event::IdentityContext {
            object_type: self.object_type.clone(),
            operation: operation.into(),
            name: self.name.clone(),
            numeric_id: self.numeric_id,
            sid: self.sid.clone(),
            primary_group_id: self.primary_group_id,
            domain: self.domain.clone(),
            home: self.home.clone(),
            shell: self.shell.clone(),
            enabled: self.enabled,
            members: self.members.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketSnapshot {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub uid: Option<u32>,
    pub inode: Option<u64>,
    pub owning_pid: Option<u32>,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{identity_snapshots, process_snapshots, socket_snapshots};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{identity_snapshots, process_snapshots, socket_snapshots};
#[cfg(windows)]
pub(crate) use windows::{
    run_json as run_powershell_json, run_powershell_command,
};

#[cfg(not(any(target_os = "linux", windows)))]
pub fn identity_snapshots(_config: &IdentityCollectorConfig) -> Result<Vec<IdentitySnapshot>> {
    Err("identity collection is unsupported on this platform".into())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn process_snapshots(_config: &ProcessCollectorConfig) -> Result<Vec<ProcessSnapshot>> {
    Err("process collection is unsupported on this platform".into())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn socket_snapshots(_config: &NetworkCollectorConfig) -> Result<Vec<SocketSnapshot>> {
    Err("network collection is unsupported on this platform".into())
}
