use super::{IdentitySnapshot, ProcessSnapshot, SocketSnapshot};
use crate::config::{IdentityCollectorConfig, NetworkCollectorConfig, ProcessCollectorConfig};
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_POWERSHELL_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_POWERSHELL_RUNTIME: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
struct WindowsIdentity {
    object_type: String,
    name: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WindowsProcess {
    pid: u32,
    #[serde(default)]
    ppid: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    executable: Option<String>,
    #[serde(default)]
    command_line: Option<String>,
    #[serde(default)]
    creation: Option<String>,
    #[serde(default)]
    session_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WindowsSocket {
    protocol: String,
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
    state: String,
    #[serde(default)]
    owning_pid: Option<u32>,
}

pub fn identity_snapshots(config: &IdentityCollectorConfig) -> Result<Vec<IdentitySnapshot>> {
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$limit = {limit}
$probeLimit = $limit + 1
$membershipEdges = 0
$rows = @()
$rows += @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE" -ErrorAction Stop | Select-Object -First $probeLimit | ForEach-Object {{
    [pscustomobject]@{{
        object_type = 'user'
        name = [string]$_.Name
        sid = if ($_.SID) {{ [string]$_.SID }} else {{ $null }}
        domain = if ($_.Domain) {{ [string]$_.Domain }} else {{ $null }}
        enabled = if ($null -ne $_.Disabled) {{ -not [bool]$_.Disabled }} else {{ $null }}
    }}
}})
$rows += @(Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount = TRUE" -ErrorAction Stop | Select-Object -First $probeLimit | ForEach-Object {{
    $group = $_
    $members = @(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser -ErrorAction Stop |
        ForEach-Object {{
            if ($_.SID) {{ [string]$_.SID }}
            elseif ($_.Domain -and $_.Name) {{ [string]::Concat([string]$_.Domain, '\', [string]$_.Name) }}
            elseif ($_.Name) {{ [string]$_.Name }}
        }} |
        Where-Object {{ $_ }} |
        Sort-Object -Unique |
        Select-Object -First $probeLimit)
    if ($members.Count -gt $limit) {{ throw "group member snapshot exceeded configured max_accounts ($limit): $($group.Name)" }}
    $membershipEdges += $members.Count
    if ($membershipEdges -gt $limit) {{ throw "identity membership snapshot exceeded configured max_accounts edge ceiling ($limit)" }}
    [pscustomobject]@{{
        object_type = 'group'
        name = [string]$group.Name
        sid = if ($group.SID) {{ [string]$group.SID }} else {{ $null }}
        domain = if ($group.Domain) {{ [string]$group.Domain }} else {{ $null }}
        enabled = $null
        members = @($members)
    }}
}})
$items = @($rows | Sort-Object object_type,name | Select-Object -First $probeLimit)
if ($items.Count -gt $limit) {{ throw "identity snapshot exceeded configured max_accounts ($limit)" }}
ConvertTo-Json -InputObject @($items) -Compress -Depth 4"#,
        limit = config.max_accounts,
    );
    let rows: Vec<WindowsIdentity> = run_json_array(&script)?;
    Ok(rows
        .into_iter()
        .map(|row| IdentitySnapshot {
            object_type: row.object_type,
            name: row.name,
            numeric_id: None,
            sid: row.sid,
            primary_group_id: None,
            domain: row.domain,
            home: None,
            shell: None,
            enabled: row.enabled,
            members: row.members,
        })
        .collect())
}

pub fn process_snapshots(config: &ProcessCollectorConfig) -> Result<Vec<ProcessSnapshot>> {
    let capture_command_line = if config.capture_command_line { "$true" } else { "$false" };
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$limit = {limit}
$probeLimit = $limit + 1
$maxCommandLine = {max_command_line}
$captureCommandLine = {capture_command_line}
$items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
    Select-Object -First $probeLimit |
    ForEach-Object {{
        $commandLine = $null
        if ($captureCommandLine -and $_.CommandLine) {{
            $commandLine = [string]$_.CommandLine
            if ($commandLine.Length -gt $maxCommandLine) {{
                $commandLine = $commandLine.Substring(0, $maxCommandLine)
            }}
        }}
        [pscustomobject]@{{
            pid = [uint32]$_.ProcessId
            ppid = [uint32]$_.ParentProcessId
            name = if ($_.Name) {{ [string]$_.Name }} else {{ $null }}
            executable = if ($_.ExecutablePath) {{ [string]$_.ExecutablePath }} else {{ $null }}
            command_line = $commandLine
            creation = if ($_.CreationDate) {{ [string]$_.CreationDate }} else {{ $null }}
            session_id = if ($null -ne $_.SessionId) {{ [uint32]$_.SessionId }} else {{ $null }}
        }}
    }})
if ($items.Count -gt $limit) {{ throw "process snapshot exceeded configured max_processes ($limit)" }}
ConvertTo-Json -InputObject @($items) -Compress -Depth 4"#,
        limit = config.max_processes,
        max_command_line = config.max_command_line_bytes,
    );
    let rows: Vec<WindowsProcess> = run_json_array(&script)?;
    Ok(rows
        .into_iter()
        .map(|row| ProcessSnapshot {
            pid: row.pid,
            start_key: row.creation.unwrap_or_else(|| format!("pid:{}", row.pid)),
            ppid: row.ppid,
            uid: None,
            gid: None,
            username: None,
            session_id: row.session_id,
            name: row.name,
            executable: row.executable,
            command_line: row
                .command_line
                .map(|value| bounded_text(&value, config.max_command_line_bytes)),
            cgroup: None,
        })
        .collect())
}

pub fn socket_snapshots(config: &NetworkCollectorConfig) -> Result<Vec<SocketSnapshot>> {
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$limit = {limit}
$probeLimit = $limit + 1
$tcp = @(Get-NetTCPConnection -ErrorAction Stop | Select-Object -First $probeLimit | ForEach-Object {{
    [pscustomobject]@{{
        protocol = if ($_.LocalAddress -like '*:*') {{ 'tcp6' }} else {{ 'tcp' }}
        local_address = [string]$_.LocalAddress
        local_port = [uint16]$_.LocalPort
        remote_address = [string]$_.RemoteAddress
        remote_port = [uint16]$_.RemotePort
        state = ([string]$_.State).ToLowerInvariant()
        owning_pid = [uint32]$_.OwningProcess
    }}
}})
if ($tcp.Count -gt $limit) {{ throw "TCP snapshot exceeded configured max_sockets ($limit)" }}
$remaining = $limit - $tcp.Count
$udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -First ($remaining + 1) | ForEach-Object {{
    [pscustomobject]@{{
        protocol = if ($_.LocalAddress -like '*:*') {{ 'udp6' }} else {{ 'udp' }}
        local_address = [string]$_.LocalAddress
        local_port = [uint16]$_.LocalPort
        remote_address = if ($_.LocalAddress -like '*:*') {{ '::' }} else {{ '0.0.0.0' }}
        remote_port = [uint16]0
        state = 'listen'
        owning_pid = [uint32]$_.OwningProcess
    }}
}})
if ($udp.Count -gt $remaining) {{ throw "combined TCP/UDP snapshot exceeded configured max_sockets ($limit)" }}
$items = @($tcp + $udp)
ConvertTo-Json -InputObject @($items) -Compress -Depth 4"#,
        limit = config.max_sockets,
    );
    let rows: Vec<WindowsSocket> = run_json_array(&script)?;
    Ok(rows
        .into_iter()
        .filter(|row| {
            config.include_loopback
                || !matches!(row.local_address.as_str(), "127.0.0.1" | "::1")
        })
        .map(|row| SocketSnapshot {
            protocol: row.protocol,
            local_address: row.local_address,
            local_port: row.local_port,
            remote_address: row.remote_address,
            remote_port: row.remote_port,
            state: row.state,
            uid: None,
            inode: None,
            owning_pid: row.owning_pid.filter(|pid| *pid != 0),
        })
        .collect())
}

fn run_json_array<T: DeserializeOwned>(script: &str) -> Result<Vec<T>> {
    let value = run_json(script)?;
    match value {
        Value::Array(_) => Ok(serde_json::from_value(value)?),
        Value::Null => Ok(Vec::new()),
        other => Ok(vec![serde_json::from_value(other)?]),
    }
}

pub(crate) fn run_json(script: &str) -> Result<Value> {
    let (status, stdout, stderr) =
        run_powershell_command(script, &[], MAX_POWERSHELL_OUTPUT_BYTES)?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(format!("PowerShell collector failed: {}", stderr.trim()).into());
    }
    let text = String::from_utf8_lossy(&stdout);
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(trimmed)?)
}

pub(crate) fn run_powershell_command(
    script: &str,
    environment: &[(&str, &OsStr)],
    max_output_bytes: usize,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &(name, value) in environment {
        command.env(name, value);
    }

    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("PowerShell stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("PowerShell stderr pipe was unavailable"))?;

    let stdout_reader = thread::spawn(move || drain_capped(stdout, max_output_bytes));
    let stderr_reader = thread::spawn(move || drain_capped(stderr, max_output_bytes));
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= MAX_POWERSHELL_RUNTIME {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| io::Error::other("PowerShell stdout reader panicked"))??;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| io::Error::other("PowerShell stderr reader panicked"))??;
    if timed_out {
        return Err(format!(
            "PowerShell command exceeded the {} second runtime ceiling",
            MAX_POWERSHELL_RUNTIME.as_secs()
        )
        .into());
    }
    if stdout_overflow || stderr_overflow {
        return Err(format!(
            "PowerShell output exceeded the {max_output_bytes} byte safety ceiling"
        )
        .into());
    }
    Ok((status, stdout, stderr))
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

fn drain_capped(mut reader: impl Read, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut overflow = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if captured.len() < max_bytes {
            let remaining = max_bytes - captured.len();
            let keep = remaining.min(read);
            captured.extend_from_slice(&buffer[..keep]);
            overflow |= keep < read;
        } else {
            overflow = true;
        }
    }
    Ok((captured, overflow))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_identity_object() {
        let value: Value = serde_json::from_str(
            r#"{"object_type":"user","name":"Administrator","sid":"S-1-5-21","enabled":false,"members":[]}"#,
        )
        .expect("json");
        let identity: WindowsIdentity = serde_json::from_value(value).expect("identity");
        assert_eq!(identity.name, "Administrator");
        assert_eq!(identity.enabled, Some(false));
        assert!(identity.members.is_empty());
    }

    #[test]
    fn bounded_text_preserves_utf8_boundaries() {
        assert_eq!(bounded_text("éclair", 1), "");
        assert_eq!(bounded_text("éclair", 2), "é");
    }

    #[test]
    fn bounded_drain_flags_overflow() {
        let input = std::io::Cursor::new(vec![1_u8; 17]);
        let (captured, overflow) = drain_capped(input, 16).expect("drain");
        assert_eq!(captured.len(), 16);
        assert!(overflow);
    }

    #[test]
    fn deserializes_single_process_object() {
        let value: Value = serde_json::from_str(
            r#"{"pid":4,"ppid":0,"name":"System","creation":"20260731010101.000000-000"}"#,
        )
        .expect("json");
        let process: WindowsProcess = serde_json::from_value(value).expect("process");
        assert_eq!(process.pid, 4);
        assert_eq!(process.name.as_deref(), Some("System"));
    }
}
