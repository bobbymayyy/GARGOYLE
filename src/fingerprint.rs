use crate::config::FingerprintConfig;
use crate::event::ImageFingerprint;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct ExecutableFingerprinter {
    config: FingerprintConfig,
    cache: HashMap<CacheKey, ImageFingerprint>,
    insertion_order: VecDeque<CacheKey>,
}

#[derive(Debug, Clone, Eq)]
struct CacheKey {
    path: PathBuf,
    size: u64,
    modified_nanos: Option<i128>,
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.size == other.size
            && self.modified_nanos == other.modified_nanos
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.size.hash(state);
        self.modified_nanos.hash(state);
    }
}

impl ExecutableFingerprinter {
    #[must_use]
    pub fn new(config: FingerprintConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn fingerprint(&mut self, executable: Option<&str>) -> Option<ImageFingerprint> {
        if !self.config.enabled {
            return None;
        }
        let executable = executable?.trim();
        if executable.is_empty() {
            return None;
        }
        let path = Path::new(executable);
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Some(ImageFingerprint {
                    sha256: None,
                    size: None,
                    modified_at: None,
                    signature_status: None,
                    signer_subject: None,
                    signer_thumbprint: None,
                    error: Some(format!("metadata: {error}")),
                });
            }
        };
        let modified = metadata.modified().ok();
        let key = CacheKey {
            path: path.to_path_buf(),
            size: metadata.len(),
            modified_nanos: modified.and_then(system_time_nanos),
        };
        if let Some(cached) = self.cache.get(&key) {
            return Some(cached.clone());
        }

        let mut fingerprint = ImageFingerprint {
            sha256: None,
            size: Some(metadata.len()),
            modified_at: modified.map(DateTime::<Utc>::from),
            signature_status: None,
            signer_subject: None,
            signer_thumbprint: None,
            error: None,
        };

        if self.config.hash_executables {
            if metadata.len() > self.config.max_file_bytes {
                fingerprint.error = Some(format!(
                    "hash skipped: file exceeds {} bytes",
                    self.config.max_file_bytes
                ));
            } else {
                match hash_sha256(path, self.config.max_file_bytes) {
                    Ok(hash) => fingerprint.sha256 = Some(hash),
                    Err(error) => fingerprint.error = Some(format!("sha256: {error}")),
                }
            }
        }

        #[cfg(windows)]
        if self.config.windows_authenticode {
            match authenticode(path) {
                Ok(signature) => {
                    fingerprint.signature_status = signature.status;
                    fingerprint.signer_subject = signature.subject;
                    fingerprint.signer_thumbprint = signature.thumbprint;
                }
                Err(error) => append_error(&mut fingerprint.error, format!("authenticode: {error}")),
            }
        }

        match fs::metadata(path) {
            Ok(after) => {
                let after_key = CacheKey {
                    path: path.to_path_buf(),
                    size: after.len(),
                    modified_nanos: after.modified().ok().and_then(system_time_nanos),
                };
                if after_key != key {
                    fingerprint.sha256 = None;
                    fingerprint.signature_status = None;
                    fingerprint.signer_subject = None;
                    fingerprint.signer_thumbprint = None;
                    append_error(
                        &mut fingerprint.error,
                        "file changed during fingerprint collection".to_owned(),
                    );
                    return Some(fingerprint);
                }
            }
            Err(error) => {
                fingerprint.sha256 = None;
                fingerprint.signature_status = None;
                fingerprint.signer_subject = None;
                fingerprint.signer_thumbprint = None;
                append_error(
                    &mut fingerprint.error,
                    format!("post-fingerprint metadata: {error}"),
                );
                return Some(fingerprint);
            }
        }

        self.insert(key, fingerprint.clone());
        Some(fingerprint)
    }

    fn insert(&mut self, key: CacheKey, value: ImageFingerprint) {
        while self.cache.len() >= self.config.max_cache_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.cache.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.cache.insert(key, value);
    }
}

fn hash_sha256(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(io::Error::other("file grew beyond hash safety ceiling"));
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn system_time_nanos(value: SystemTime) -> Option<i128> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some(i128::try_from(duration.as_nanos()).ok()?),
        Err(error) => Some(-i128::try_from(error.duration().as_nanos()).ok()?),
    }
}

fn append_error(target: &mut Option<String>, message: String) {
    match target {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&message);
        }
        None => *target = Some(message),
    }
}

#[cfg(windows)]
#[derive(Debug, serde::Deserialize)]
struct AuthenticodeResult {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    thumbprint: Option<String>,
}

#[cfg(windows)]
fn authenticode(path: &Path) -> crate::Result<AuthenticodeResult> {
    use crate::platform::run_powershell_command;

    let script = r#"$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $env:GARGOYLE_IMAGE_PATH
[pscustomobject]@{
    status = if ($signature.Status) { [string]$signature.Status } else { $null }
    subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
    thumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
} | ConvertTo-Json -Compress -Depth 3"#;
    let environment = [("GARGOYLE_IMAGE_PATH", path.as_os_str())];
    let (status, stdout, stderr) =
        run_powershell_command(script, &environment, 1024 * 1024)?;
    if !status.success() {
        return Err(format!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )
        .into());
    }
    let text = String::from_utf8_lossy(&stdout);
    Ok(serde_json::from_str(text.trim_start_matches('\u{feff}').trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("sample.bin");
        fs::write(&path, b"abc").expect("fixture");
        assert_eq!(
            hash_sha256(&path, 1024).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn refuses_to_hash_past_ceiling() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("sample.bin");
        fs::write(&path, b"abcd").expect("fixture");
        assert!(hash_sha256(&path, 3).is_err());
    }
}
