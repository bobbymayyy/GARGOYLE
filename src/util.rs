use crate::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub fn read_limited(path: impl AsRef<Path>, max_bytes: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(8192));
    let mut limited = file.take(max_bytes as u64);
    limited.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn read_string_limited(path: impl AsRef<Path>, max_bytes: usize) -> Result<String> {
    let bytes = read_limited(path, max_bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn read_limited_checked(path: impl AsRef<Path>, max_bytes: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("read ceiling overflow"))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(8192));
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(format!("input exceeded {max_bytes} byte safety ceiling").into());
    }
    Ok(bytes)
}

pub fn read_string_limited_checked(path: impl AsRef<Path>, max_bytes: usize) -> Result<String> {
    let bytes = read_limited_checked(path, max_bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[must_use]
pub fn sanitize_identifier(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .take(128)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

#[must_use]
pub fn hostname() -> String {
    platform_hostname().unwrap_or_else(|| "unknown-host".to_owned())
}

#[cfg(target_os = "linux")]
fn platform_hostname() -> Option<String> {
    read_string_limited("/etc/hostname", 4096)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(windows)]
fn platform_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn platform_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub fn sleep_interruptible(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_agent_identifiers() {
        assert_eq!(sanitize_identifier("lab host/01"), "lab_host_01");
        assert_eq!(sanitize_identifier(""), "unknown");
    }

    #[test]
    fn checked_read_rejects_truncation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("large.txt");
        std::fs::write(&path, b"abcd").expect("fixture");
        assert!(read_limited_checked(&path, 3).is_err());
    }
}
