use super::{IdentitySnapshot, ProcessSnapshot, SocketSnapshot};
use crate::config::{IdentityCollectorConfig, NetworkCollectorConfig, ProcessCollectorConfig};
use crate::util::{read_limited, read_string_limited, read_string_limited_checked};
use crate::Result;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub fn identity_snapshots(config: &IdentityCollectorConfig) -> Result<Vec<IdentitySnapshot>> {
    const MAX_IDENTITY_FILE_BYTES: usize = 8 * 1024 * 1024;

    let passwd = read_identity_file(&config.linux_passwd_path, MAX_IDENTITY_FILE_BYTES)?;
    let group = read_identity_file(&config.linux_group_path, MAX_IDENTITY_FILE_BYTES)?;
    let users = parse_passwd(&passwd);
    let mut groups = parse_group(&group);
    merge_primary_group_memberships(&users, &mut groups);
    let mut snapshots = users;
    snapshots.extend(groups);
    if snapshots.is_empty() {
        return Err("identity sources contained no parseable accounts or groups".into());
    }
    if snapshots.len() > config.max_accounts {
        return Err(format!(
            "identity snapshot exceeded configured max_accounts ({})",
            config.max_accounts
        )
        .into());
    }
    Ok(snapshots)
}

fn read_identity_file(path: &Path, max_bytes: usize) -> Result<String> {
    read_string_limited_checked(path, max_bytes).map_err(|error| -> crate::BoxError {
        format!("identity source {} could not be read safely: {error}", path.display()).into()
    })
}

fn parse_passwd(content: &str) -> Vec<IdentitySnapshot> {
    content
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 7 || fields[0].is_empty() {
                return None;
            }
            let uid = fields[2].parse::<u32>().ok()?;
            let primary_group_id = fields[3].parse::<u32>().ok();
            Some(IdentitySnapshot {
                object_type: "user".to_owned(),
                name: fields[0].to_owned(),
                numeric_id: Some(uid),
                sid: None,
                primary_group_id,
                domain: None,
                home: nonempty(fields[5]),
                shell: nonempty(fields[6]),
                enabled: Some(!matches!(
                    fields[6],
                    "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false"
                )),
                members: Vec::new(),
            })
        })
        .collect()
}

fn parse_group(content: &str) -> Vec<IdentitySnapshot> {
    content
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 4 || fields[0].is_empty() {
                return None;
            }
            let gid = fields[2].parse::<u32>().ok()?;
            let mut members = fields[3]
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            members.sort_unstable();
            members.dedup();
            Some(IdentitySnapshot {
                object_type: "group".to_owned(),
                name: fields[0].to_owned(),
                numeric_id: Some(gid),
                sid: None,
                primary_group_id: None,
                domain: None,
                home: None,
                shell: None,
                enabled: None,
                members,
            })
        })
        .collect()
}

fn merge_primary_group_memberships(
    users: &[IdentitySnapshot],
    groups: &mut [IdentitySnapshot],
) {
    let group_indexes = groups
        .iter()
        .enumerate()
        .filter_map(|(index, group)| group.numeric_id.map(|gid| (gid, index)))
        .collect::<HashMap<_, _>>();
    for user in users {
        let Some(gid) = user.primary_group_id else {
            continue;
        };
        let Some(group) = group_indexes
            .get(&gid)
            .and_then(|index| groups.get_mut(*index))
        else {
            continue;
        };
        group.members.push(user.name.clone());
    }
    for group in groups {
        group.members.sort_unstable();
        group.members.dedup();
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

pub fn process_snapshots(config: &ProcessCollectorConfig) -> Result<Vec<ProcessSnapshot>> {
    let usernames = read_usernames();
    let mut snapshots = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(snapshot) = read_process(pid, config, &usernames) {
            if snapshots.len() >= config.max_processes {
                return Err(format!(
                    "process snapshot exceeded configured max_processes ({})",
                    config.max_processes
                )
                .into());
            }
            snapshots.push(snapshot);
        }
    }
    Ok(snapshots)
}

pub fn socket_snapshots(config: &NetworkCollectorConfig) -> Result<Vec<SocketSnapshot>> {
    let owners = if config.correlate_processes {
        socket_owners(config.max_fds_per_process, config.max_sockets)?
    } else {
        HashMap::new()
    };
    let mut sockets = Vec::new();
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        let content = read_string_limited_checked(path, 64 * 1024 * 1024)?;
        for line in content.lines().skip(1) {
            let Some(mut socket) = parse_socket_line(line, protocol, ipv6) else {
                continue;
            };
            if !config.include_loopback
                && socket
                    .local_address
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
            {
                continue;
            }
            socket.owning_pid = socket.inode.and_then(|inode| owners.get(&inode).copied());
            if sockets.len() >= config.max_sockets {
                return Err(format!(
                    "socket snapshot exceeded configured max_sockets ({})",
                    config.max_sockets
                )
                .into());
            }
            sockets.push(socket);
        }
    }
    Ok(sockets)
}

fn read_process(
    pid: u32,
    config: &ProcessCollectorConfig,
    usernames: &HashMap<u32, String>,
) -> Option<ProcessSnapshot> {
    let base = Path::new("/proc").join(pid.to_string());
    let stat = read_string_limited(base.join("stat"), 64 * 1024).ok()?;
    let start_ticks = parse_start_ticks(&stat)?;
    let status = read_string_limited(base.join("status"), 64 * 1024).unwrap_or_default();
    let name = status_value(&status, "Name").map(str::to_owned);
    let ppid = status_value(&status, "PPid").and_then(|value| value.parse().ok());
    let uid = status_value(&status, "Uid")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok());
    let gid = status_value(&status, "Gid")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok());
    let executable = fs::read_link(base.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let command_line = if config.capture_command_line {
        read_command_line(&base.join("cmdline"), config.max_command_line_bytes)
    } else {
        None
    };
    let cgroup = read_string_limited(base.join("cgroup"), 64 * 1024)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let session_id = read_string_limited(base.join("sessionid"), 64)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| *value != u32::MAX);

    Some(ProcessSnapshot {
        pid,
        start_key: start_ticks.to_string(),
        ppid,
        uid,
        gid,
        username: uid.and_then(|value| usernames.get(&value).cloned()),
        session_id,
        name,
        executable,
        command_line,
        cgroup,
    })
}

fn socket_owners(
    max_fds_per_process: usize,
    max_socket_owners: usize,
) -> Result<HashMap<u64, u32>> {
    const MAX_PROCESSES_SCANNED: usize = 1_000_000;

    let mut owners = HashMap::new();
    let mut processes_scanned = 0_usize;
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        processes_scanned = processes_scanned.saturating_add(1);
        if processes_scanned > MAX_PROCESSES_SCANNED {
            return Err(format!(
                "socket-owner scan exceeded process safety ceiling ({MAX_PROCESSES_SCANNED})"
            )
            .into());
        }
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let mut scanned = 0_usize;
        for fd in fds {
            let fd = match fd {
                Ok(fd) => fd,
                Err(_) => continue,
            };
            scanned = scanned.saturating_add(1);
            if scanned > max_fds_per_process {
                return Err(format!(
                    "file-descriptor snapshot for pid {pid} exceeded configured max_fds_per_process ({max_fds_per_process})"
                )
                .into());
            }
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let value = target.to_string_lossy();
            let Some(inode) = parse_socket_inode(&value) else {
                continue;
            };
            if !owners.contains_key(&inode) && owners.len() >= max_socket_owners {
                return Err(format!(
                    "socket-owner snapshot exceeded configured max_sockets ({max_socket_owners})"
                )
                .into());
            }
            owners
                .entry(inode)
                .and_modify(|owner| *owner = (*owner).min(pid))
                .or_insert(pid);
        }
    }
    Ok(owners)
}

fn parse_socket_inode(value: &str) -> Option<u64> {
    value
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn read_usernames() -> HashMap<u32, String> {
    read_string_limited_checked("/etc/passwd", 4 * 1024 * 1024)
        .map(|content| {
            content
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?.to_owned();
                    let _password = fields.next()?;
                    let uid = fields.next()?.parse().ok()?;
                    Some((uid, name))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name == key).then_some(value.trim())
    })
}

fn parse_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn read_command_line(path: &Path, max_bytes: usize) -> Option<String> {
    let bytes = read_limited(path, max_bytes).ok()?;
    let value = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    (!value.is_empty()).then_some(value)
}

fn parse_socket_line(line: &str, protocol: &str, ipv6: bool) -> Option<SocketSnapshot> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (local_address, local_port) = parse_endpoint(fields[1], ipv6)?;
    let (remote_address, remote_port) = parse_endpoint(fields[2], ipv6)?;
    Some(SocketSnapshot {
        protocol: protocol.to_owned(),
        local_address,
        local_port,
        remote_address,
        remote_port,
        state: socket_state(fields[3]).to_owned(),
        uid: fields.get(7).and_then(|value| value.parse().ok()),
        inode: fields.get(9).and_then(|value| value.parse().ok()),
        owning_pid: None,
    })
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<(String, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if ipv6 {
        decode_ipv6(address)?.to_string()
    } else {
        let raw = u32::from_str_radix(address, 16).ok()?;
        Ipv4Addr::from(raw.to_le_bytes()).to_string()
    };
    Some((address, port))
}

fn decode_ipv6(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for index in 0..4 {
        let start = index * 8;
        let word = u32::from_str_radix(value.get(start..start + 8)?, 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn socket_state(value: &str) -> &'static str {
    match value {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        "0C" => "new_syn_recv",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_sources() {
        let users = parse_passwd("may:x:1000:1000:May:/home/may:/bin/bash\n");
        assert_eq!(users[0].name, "may");
        assert_eq!(users[0].primary_group_id, Some(1000));
        assert_eq!(users[0].enabled, Some(true));

        let groups = parse_group("sudo:x:27:may,admin,may\n");
        assert_eq!(groups[0].members, vec!["admin", "may"]);
    }

    #[test]
    fn primary_groups_include_their_users() {
        let users = parse_passwd(
            "may:x:1000:1000:May:/home/may:/bin/bash\nadmin:x:1001:27:Admin:/home/admin:/bin/bash\n",
        );
        let mut groups = parse_group("may:x:1000:\nsudo:x:27:may\n");
        merge_primary_group_memberships(&users, &mut groups);

        assert_eq!(groups[0].members, vec!["may"]);
        assert_eq!(groups[1].members, vec!["admin", "may"]);
    }

    #[test]
    fn nonempty_rejects_empty_values() {
        assert_eq!(nonempty(""), None);
        assert_eq!(nonempty("/bin/bash").as_deref(), Some("/bin/bash"));
    }

    #[test]
    fn parses_start_ticks_from_proc_stat() {
        let stat = "42 (hello world) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20";
        assert_eq!(parse_start_ticks(stat), Some(999));
    }

    #[test]
    fn parses_socket_inode_target() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("pipe:[12345]"), None);
    }

    #[test]
    fn parses_proc_socket_line() {
        let line = concat!(
            "0: 0100007F:0016 00000000:0000 0A ",
            "00000000:00000000 00:00000000 00000000 1000 0 12345 1"
        );
        let socket = parse_socket_line(line, "tcp", false).expect("socket");
        assert_eq!(socket.local_address, "127.0.0.1");
        assert_eq!(socket.local_port, 22);
        assert_eq!(socket.state, "listen");
        assert_eq!(socket.inode, Some(12345));
    }
}
