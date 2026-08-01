# GARGOYLE Roadmap

## v0.1: Stone wakes

Status: implemented.

- normalized v1 schema
- bounded pipeline
- Linux process, network, filesystem, kernel, and health polling
- local outputs, strict configuration, hardening, and CI

## v0.2: Eyes and fingerprints

Status: implemented in source, pending trusted Cargo build and committed lockfile.

- socket ownership and process correlation
- process/socket lifecycle closure events
- SHA-256 executable identity
- Windows Authenticode enrichment
- semantic local user/group and group-membership changes
- Linux SSH/sudo/`su` authentication parsing
- Windows Security Event Log normalization
- first-class Windows build, deployment, CI, release assets, and bounded PowerShell adapter boundary
- v2 event schema
- parser fuzz scaffolding
- coverage floor and benchmark harness
- journald and JSONL rotation guidance

Remaining release gate:

- generate and review `Cargo.lock`
- pass Linux and Windows CI on a networked trusted builder
- record measured baseline data in `docs/PERFORMANCE.md`

## v0.3: Faster wings

- netlink process and network collectors
- fanotify or Linux audit filesystem backend
- Windows Event Tracing or native event subscription evaluation
- collector capability discovery and polling fallback
- collector lag and source-loss metrics

## v0.4: Sealed orders

- signed configuration and policy bundles
- local control socket/pipe
- authenticated local forwarder protocol
- syslog output
- remote forwarding outside the privileged core

## v0.5: Packaged guardian

- Debian and RPM packages
- Windows signed installer/package
- reproducible builds
- signed repository metadata
- SBOM and provenance verification guide
- Ansible role for DIP/DIPx and standalone hosts

## v1.0 gates

- stable event and configuration contracts
- audited privileged parser/adapter boundaries
- measured performance envelope
- continuous fuzzing and security regression suite
- supported upgrade and rollback path
- compatibility tests with shared SENTINEL behavioral expectations
