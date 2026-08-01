# Changelog

All notable changes to Project GARGOYLE are documented here.

## [Unreleased]

## [0.2.0] - 2026-07-31

### Added

- supported Windows process, network, filesystem, identity, authentication, and health collection
- Security Event Log normalization for events 4624, 4625, 4648, 4672, and 4688
- executable SHA-256 fingerprints on Linux and Windows
- Windows Authenticode status, subject, and thumbprint collection
- socket-to-process ownership correlation and optional process fingerprint attachment
- process stop and socket/listener closure events
- semantic local user, group, and group-membership add/remove/change events with explicit member deltas
- bounded Linux authentication-log tails for SSH, sudo, and `su`
- Linux primary-GID membership folding so account-to-group relationships are not missed
- `gargoyle.event/v2` with OS/architecture, identity, authentication, richer process, network, and file contexts
- Windows configuration, smoke test, SYSTEM startup-task installer, CI job, release archive, checksums, and attestation
- parser fuzz targets, coverage floor, benchmark harness, journald directives, and logrotate profile

### Changed

- agent description and architecture are now cross-platform
- policy can match executable hash, Authenticode status/signer thumbprint, authentication account/outcome/logon type, and identity name/operation
- direct dependency graph now includes exact-pinned `sha2`

### Security

- concurrently bounded PowerShell stdout/stderr capture, a 30-second adapter runtime ceiling, and bounded JSON parsing
- fixed project-owned PowerShell programs with no observed-host-text command interpolation
- one command-line privacy switch suppresses process snapshots, sudo command details, and Windows 4688 command-line enrichment
- hardened Windows installation directory ACL
- fail-closed process, socket, filesystem, account, and Linux descriptor snapshot ceilings
- Windows Security-log cursor recovery after log clearing or record-ID rollover

## [0.1.0] - 2026-07-31

### Added

- initial hardened Rust agent architecture
- process, network, filesystem, kernel, and health collectors
- normalized `gargoyle.event/v1` JSON event contract
- bounded queue, policy engine, metrics, and local outputs
- native and container deployment profiles
- CI, security, coverage, SBOM, checksum, and provenance workflows
- architecture, threat model, event, and roadmap documentation
