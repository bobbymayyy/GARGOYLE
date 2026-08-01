# GARGOYLE Threat Model

## Assets

- host availability and performance
- sensitive process, account, authentication, and executable metadata
- integrity and continuity of emitted telemetry
- policy and configuration integrity
- privileged execution context
- operator trust in event meaning

## Adversary control

An attacker may influence process names and arguments, paths, symlinks, socket churn, authentication log text, Windows event fields, executable files, account names, and rapidly changing state. A kernel-level attacker can deceive or blind a userspace observer; GARGOYLE does not claim otherwise.

## Memory and parser safety

Controls:

- safe Rust only with `unsafe_code = "forbid"`
- bounded file, command-line, event-log, account, process, socket, and PowerShell-output inputs
- typed deserialization with collector failure isolation
- fuzz targets for configuration and event JSON

## Resource exhaustion

Controls:

- bounded nonblocking event queue
- configurable polling intervals
- explicit process/socket/file/account and per-process descriptor ceilings
- fail-closed snapshots that retain the last complete state
- bounded executable hashing and cache size
- bounded authentication reads/events per poll
- event-loss and error counters

Residual risk: extreme churn can produce drops or expensive repeated snapshots. Health events make this degradation observable.

## Secret collection

Controls:

- command-line capture disabled by default, including sudo command details and Windows 4688 command-line enrichment
- filesystem collector reads metadata, not file content
- executable hashing is opt-out and size-bounded
- Authenticode collection returns certificate identity, not private material
- restrictive local output permissions
- no built-in remote output

Residual risk: paths, usernames, hashes, certificate subjects, authentication sources, and optional command lines can be sensitive. Operators must apply retention and access controls.

## Subprocess and command injection

Linux collectors do not execute host commands. Windows requires project-owned PowerShell adapters for supported management surfaces.

Controls:

- no general command configuration
- no observed host text interpolated into scripts
- only validated numeric limits are formatted into scripts
- file paths are passed through environment variables when needed
- `-NoProfile -NonInteractive` execution
- concurrent bounded stdout/stderr capture before JSON parsing
- a fixed 30-second PowerShell adapter runtime ceiling
- Security workflow rejects Unix shell construction in Rust

Residual risk: compromise of `powershell.exe`, management providers, or the host's PowerShell modules can falsify results.

## Privilege abuse

Controls:

- observation-only core
- no remote command runner or host mutation policy action
- hardened systemd/AppArmor/container deployment
- Windows startup task runs a fixed executable and config under SYSTEM
- ProgramData ACL limited to SYSTEM and Administrators
- strict configuration with unknown-field rejection

## Telemetry tampering

Current controls:

- versioned schema
- sequence numbers and timestamps
- OS/architecture/agent identity
- local restrictive outputs
- checksummed and attested releases

Planned controls include signed configuration, signed event batches, and authenticated forwarding.

## Supply chain

- pinned toolchain and exact direct dependencies
- release-required Cargo lockfile
- audit, deny, and unused-dependency checks
- immutable Action SHAs
- Linux and Windows CI
- SBOMs, checksums, and provenance attestations

## Non-goals

GARGOYLE is not an antivirus, a complete EDR, a kernel rootkit detector, a remote administration tool, a general scripting host, or an evidence repository by itself.
