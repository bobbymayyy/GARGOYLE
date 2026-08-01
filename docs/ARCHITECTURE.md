# GARGOYLE Architecture

## Design objectives

GARGOYLE is a privileged observer, so the architecture optimizes for memory safety, bounded resource use, stable event semantics, explicit degradation, platform isolation, and deployability without a remote-control plane.

## Runtime model

Each enabled collector owns one thread and a private previous-state snapshot. Poll results are normalized into `Event` values and submitted with `try_send` to a bounded `sync_channel`. A slow sink cannot freeze collection. Full queues drop the newest event and increment `queue_drops`. Snapshot ceilings fail the poll before replacing prior state, preventing truncated inventories from becoming fabricated removal events.

One pipeline thread applies ordered policy and writes to configured sinks. A shutdown signal flips an atomic flag, collectors finish, senders close, the pipeline drains, and `agent.stopped` is written directly after the drain so queue saturation cannot deadlock shutdown.

## Platform boundary

`src/platform/` exposes typed snapshots:

- `ProcessSnapshot`
- `SocketSnapshot`
- `IdentitySnapshot`

Collectors depend on these types, not on `/proc`, CIM, or PowerShell details. Linux and Windows implementations can evolve independently while emitting the same event families.

### Linux adapters

- `/proc/<pid>` for process lifecycle
- `/proc/net/*` plus `/proc/<pid>/fd` socket-inode ownership
- `/etc/passwd` and `/etc/group` semantic identity state
- bounded tails of configured authentication logs
- `/proc/modules`, taint, and lockdown state

### Windows adapters

- `Win32_Process` through CIM
- `Get-NetTCPConnection` and `Get-NetUDPEndpoint`
- local `Win32_UserAccount` and `Win32_Group` CIM classes plus `Win32_GroupUser` associations
- `Get-WinEvent` Security records
- `Get-AuthenticodeSignature`

Windows PowerShell is an adapter boundary, not a general scripting feature. Scripts are project-owned constants or format only validated numeric limits. Observed paths are supplied through environment variables. Stdout and stderr are drained concurrently into bounded buffers, each invocation has a 30-second runtime ceiling, and JSON is parsed only after those checks pass.

## Fingerprinting

`ExecutableFingerprinter` records bounded metadata and optionally SHA-256. Windows builds may additionally collect Authenticode status and certificate identity. Cache keys combine path, size, and modification timestamp; cache size is bounded.

A missing or inaccessible image does not fail the parent event. The fingerprint context records an error so telemetry preserves both the event and the reason enrichment failed.

## Collector semantics

### Process

Tracks PID plus a platform start key to distinguish PID reuse. Emits `process.start` and optional `process.stop`. Windows Security event 4688 may emit the separate high-fidelity `process.audit_start` stream.

### Network

Tracks socket state and owning PID. New endpoints emit `network.listen` or `network.connect`; removed endpoints emit closure events. Process context is attached when correlation succeeds.

### Filesystem

Recursively snapshots configured paths with bounded depth/file count. It reads metadata rather than content and normalizes Unix ownership fields as optional on Windows.

### Identity

Diffs semantic account and group records, including sorted group membership. Linux folds primary-GID membership from `/etc/passwd` into supplemental membership from `/etc/group`; Windows uses CIM associations. Membership-only changes emit `identity.group_membership_changed` with added and removed member deltas. This is separate from raw password-database file changes, allowing policy to distinguish a specific account or privileged-group membership change from generic metadata churn.

### Authentication

Linux parses bounded appended log records for SSH, sudo, and `su`. Windows normalizes selected Security Event Log records and tracks Record IDs to avoid replaying the full log by default.

### Kernel

Linux-only module, taint, and lockdown collection. Configuration rejects an enabled kernel collector on unsupported platforms.

### Health

Emits uptime and internal counters, including queue drops, collector errors, sink errors, and successful process correlations.

## Outputs

- stdout JSONL on all supported platforms
- append-only JSONL file on all supported platforms
- Unix datagram on Unix only

Linux file output uses `O_NOFOLLOW` and mode `0600`. Windows deployment protects the parent directory ACL. Remote transmission remains outside the privileged core.

## Future boundaries

A workspace split becomes useful once contracts stabilize:

- `gargoyle-core`
- `gargoyle-linux`
- `gargoyle-windows`
- `gargoyled`
- `gargoylectl`
- optional event-driven backend crates
