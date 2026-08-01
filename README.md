# Project GARGOYLE

> **The rusted watchdog.** A hardened Linux and Windows telemetry agent written in Rust.

GARGOYLE is the Rust counterpart to SENTINEL: a small, auditable security observer that turns host state into normalized JSON events without becoming a remote-control framework. The v0.2 line, **Eyes and Fingerprints**, adds process ownership, executable identity, semantic authentication, local account changes, and a supported Windows build.

## v0.2 capabilities

### Linux

- process start and stop detection with PID-reuse protection
- TCP/UDP listeners and connections correlated to owning processes
- SHA-256 executable fingerprints
- sensitive-file metadata changes
- semantic local user, group, and group-membership changes
- SSH, sudo, and `su` authentication events from bounded log tails
- kernel module, taint, and lockdown changes
- systemd, AppArmor, logrotate, and container deployment assets

### Windows

- process start and stop snapshots through CIM
- TCP/UDP endpoint ownership through NetTCPIP cmdlets
- SHA-256 and Authenticode executable identity
- sensitive registry-hive, hosts, and OpenSSH artifact metadata changes
- semantic local user, group, and group-membership changes through CIM associations
- Security Event Log normalization for events 4624, 4625, 4648, 4672, and 4688
- hardened ProgramData installation and SYSTEM startup-task deployment
- Windows CI, smoke testing, release ZIPs, checksums, and attestations

Windows Security event availability depends on local audit policy. Event 4688 command-line data is optional and should be enabled only after considering its secret-collection impact.

## Event contract

Every output line is one `gargoyle.event/v2` JSON object. Context is attached only when relevant.

```json
{
  "schema_version": "gargoyle.event/v2",
  "event_id": "gargoyle-host-1770000000000000000-12",
  "sequence": 12,
  "timestamp": "2026-07-31T23:20:00Z",
  "agent": {
    "id": "gargoyle-host",
    "hostname": "host",
    "version": "0.2.0",
    "os": "windows",
    "arch": "x86_64"
  },
  "collector": "network",
  "kind": "network.listen",
  "severity": "high",
  "message": "new tcp listener on 0.0.0.0:22 owned by pid 812",
  "process": {
    "pid": 812,
    "name": "sshd.exe",
    "executable": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
    "fingerprint": {
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "signature_status": "Valid"
    }
  },
  "network": {
    "protocol": "tcp",
    "local_address": "0.0.0.0",
    "local_port": 22,
    "remote_address": "0.0.0.0",
    "remote_port": 0,
    "state": "listen",
    "owning_pid": 812
  }
}
```

The canonical schema is [`schemas/event.schema.json`](schemas/event.schema.json). v2 is intentionally a schema bump because agent identity and several context models changed.

## Build and test

The repository pins Rust 1.97.1 and declares Rust 1.85 as the minimum supported version.

```bash
rustup toolchain install 1.97.1 --profile minimal --component clippy,rustfmt
cargo generate-lockfile
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --locked
```

The source bundle does not invent a `Cargo.lock`. Generate it on a trusted networked builder, review the transitive graph, and commit it before release. Release automation refuses unlocked builds.

### Linux smoke test

```bash
./scripts/smoke-test.sh ./target/release/gargoyle
```

### Windows smoke test

```powershell
.\scripts\smoke-test.ps1 -Binary .\target\release\gargoyle.exe
```

## Run locally

### Linux

```bash
cargo run -- print-default-config > gargoyle.toml
cargo run -- validate --config gargoyle.toml
sudo cargo run -- run --config gargoyle.toml
```

### Windows

```powershell
cargo run -- print-default-config | Set-Content .\gargoyle.toml
cargo run -- validate --config .\gargoyle.toml
cargo run -- run --config .\gargoyle.toml
```

Administrative or SYSTEM execution is recommended for complete process metadata, protected files, Authenticode inspection, and the Security log.

## Installation

### Linux systemd

```bash
cargo build --release
sudo ./scripts/install.sh target/release/gargoyle config/gargoyle.example.toml
sudo systemctl enable --now gargoyle
journalctl -u gargoyle -f
```

The supplied service emits to journald by default. Optional JSONL output is covered by `packaging/logrotate/gargoyle`.

### Windows startup task

From elevated PowerShell:

```powershell
cargo build --release
.\packaging\windows\install.ps1 `
  -BinaryPath .\target\release\gargoyle.exe `
  -ConfigPath .\config\gargoyle.windows.toml
```

This installs under `C:\ProgramData\GARGOYLE`, restricts the directory ACL to SYSTEM and Administrators, validates the configuration, registers a highest-privilege SYSTEM task at startup, and starts it. It does not masquerade as a Windows service without implementing the Service Control Manager protocol.

See [`docs/WINDOWS.md`](docs/WINDOWS.md) for audit-policy and operational details.

## Configuration and policy

Start from:

- Linux: [`config/gargoyle.example.toml`](config/gargoyle.example.toml)
- Windows: [`config/gargoyle.windows.toml`](config/gargoyle.windows.toml)
- container host sensor: [`config/gargoyle.container.toml`](config/gargoyle.container.toml)

Command-line capture is disabled by default because arguments routinely contain credentials, tokens, and personal data. The same switch suppresses sudo command details and Windows event 4688 command-line enrichment. Executable hashing is bounded by file size and cached by path, size, and modification time.

Policy can match collector, event kind, path prefix, process name, process SHA-256, Authenticode status, signer thumbprint, authentication account/outcome/logon type, identity name/operation, and local/remote ports. Actions are `allow`, `drop`, and `set_severity`; matching rules may also add labels.

## Architecture

```text
Linux / Windows host surfaces
  │
  ├── process lifecycle ─── executable fingerprint
  ├── sockets ───────────── owning process correlation
  ├── filesystem metadata
  ├── local identity state
  ├── authentication logs
  ├── Linux kernel state
  └── health metrics
            │
            ▼
      bounded sync_channel
            │
            ▼
        policy engine
            │
            ▼
 stdout / JSONL / Unix datagram
```

Collectors never write directly to outputs. They submit normalized events to a bounded nonblocking channel. One pipeline thread applies policy and serializes events. Queue saturation is visible through metrics instead of silently freezing privileged collection.

Windows adapters execute only project-owned, fixed PowerShell programs with numeric configuration substitutions or environment-variable path passing. Stdout and stderr are bounded while they are captured, each adapter invocation has a 30-second runtime ceiling, and snapshot ceilings fail closed instead of publishing partial state. No observed host text is interpolated into a command program.

## Security posture

- `#![forbid(unsafe_code)]`
- exact direct dependency pins and release-required lockfile
- bounded queue, file reads, process/socket/file/account snapshots, per-process descriptor scans, PowerShell capture, and PowerShell runtime
- strict TOML with unknown-field rejection
- command-line capture off by default
- read-only observation with no remote command facility
- hardened Linux and Windows deployment profiles
- immutable GitHub Action pins
- Linux and Windows CI
- audit, deny, dependency-pruning, coverage, fuzz scaffolding, SBOMs, checksums, and provenance attestations

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before expanding privileged collection surfaces.

## Repository map

```text
src/collectors/        normalized collectors
src/platform/          Linux and Windows host adapters
src/fingerprint.rs     SHA-256 and Authenticode identity
config/                platform and container examples
docs/                  architecture, events, operations, roadmap, threat model
schemas/               JSON Schema contracts
packaging/systemd/     Linux service hardening
packaging/windows/     Windows install/uninstall scripts
packaging/logrotate/   optional JSONL rotation
fuzz/                   cargo-fuzz targets
.github/workflows/     Linux/Windows CI, security, coverage, release
```

## License

Licensed under either Apache License 2.0 or MIT, at your option.
