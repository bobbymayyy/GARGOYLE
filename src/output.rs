use crate::config::OutputConfig;
use crate::event::Event;
use crate::Result;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

pub trait Sink: Send {
    fn write(&mut self, event: &Event) -> Result<()>;
}

pub struct CompositeSink {
    sinks: Vec<Box<dyn Sink>>,
}

impl std::fmt::Debug for CompositeSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeSink")
            .field("sink_count", &self.sinks.len())
            .finish()
    }
}

impl CompositeSink {
    pub fn from_config(config: &OutputConfig) -> Result<Self> {
        let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
        if config.stdout {
            sinks.push(Box::new(StdoutSink::new(config.flush_each_event)));
        }
        if let Some(path) = &config.file {
            sinks.push(Box::new(FileSink::open(path, config.flush_each_event)?));
        }
        if let Some(path) = &config.unix_datagram {
            #[cfg(unix)]
            sinks.push(Box::new(UnixDatagramSink::new(path.clone())?));
            #[cfg(not(unix))]
            return Err(format!(
                "Unix datagram output is unavailable on {}: {}",
                std::env::consts::OS,
                path.display()
            )
            .into());
        }
        Ok(Self { sinks })
    }

    pub fn write(&mut self, event: &Event) -> Result<()> {
        let mut failures = Vec::new();
        for sink in &mut self.sinks {
            if let Err(error) = sink.write(event) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; ").into())
        }
    }
}

struct StdoutSink {
    writer: BufWriter<io::Stdout>,
    flush_each_event: bool,
}

impl StdoutSink {
    fn new(flush_each_event: bool) -> Self {
        Self {
            writer: BufWriter::new(io::stdout()),
            flush_each_event,
        }
    }
}

impl Sink for StdoutSink {
    fn write(&mut self, event: &Event) -> Result<()> {
        write_json_line(&mut self.writer, event, self.flush_each_event)
    }
}

struct FileSink {
    writer: BufWriter<File>,
    flush_each_event: bool,
}

impl FileSink {
    fn open(path: &Path, flush_each_event: bool) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        refuse_existing_symlink(path)?;
        let file = secure_open_append(path)?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            writer: BufWriter::new(file),
            flush_each_event,
        })
    }
}

impl Sink for FileSink {
    fn write(&mut self, event: &Event) -> Result<()> {
        write_json_line(&mut self.writer, event, self.flush_each_event)
    }
}

#[cfg(unix)]
struct UnixDatagramSink {
    socket: UnixDatagram,
    destination: std::path::PathBuf,
}

#[cfg(unix)]
impl UnixDatagramSink {
    fn new(destination: std::path::PathBuf) -> Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            destination,
        })
    }
}

#[cfg(unix)]
impl Sink for UnixDatagramSink {
    fn write(&mut self, event: &Event) -> Result<()> {
        let mut bytes = serde_json::to_vec(event)?;
        bytes.push(b'\n');
        self.socket.send_to(&bytes, &self.destination)?;
        Ok(())
    }
}

#[cfg(unix)]
fn secure_open_append(path: &Path) -> io::Result<File> {
    const O_NOFOLLOW: i32 = 0o400000;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn secure_open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn refuse_existing_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::other(
            "refusing to write events through a symbolic link",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_json_line(writer: &mut impl Write, event: &Event, flush: bool) -> Result<()> {
    serde_json::to_writer(&mut *writer, event)?;
    writer.write_all(b"\n")?;
    if flush {
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventFactory, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn writes_one_json_object_per_line() {
        let factory = EventFactory::new("agent".into(), "host".into(), BTreeMap::new());
        let event = factory.event("test", "test.event", Severity::Info, "hello");
        let mut bytes = Vec::new();
        write_json_line(&mut bytes, &event, false).expect("write");
        assert!(bytes.ends_with(b"\n"));
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(decoded["kind"], "test.event");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_file_output() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.jsonl");
        let link = directory.path().join("events.jsonl");
        fs::write(&target, b"").expect("target file");
        symlink(&target, &link).expect("symlink");

        assert!(FileSink::open(&link, true).is_err());
    }
}
