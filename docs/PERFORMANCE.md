# Performance Budget

The v0.2 collectors are polling implementations. Their purpose is a trustworthy baseline, not zero-cost invisibility.

## Initial budget

For an otherwise idle small host with default intervals:

- steady-state resident memory: target below 64 MiB
- average CPU: target below 2 percent of one logical core
- event queue: fixed at 4,096 entries by default
- no sustained queue drops at baseline
- one collection cycle should finish before its next configured interval

These are release budgets, not measured claims. A trusted Linux and Windows build must record hardware, OS build, workload, mean/max RSS, CPU, collector errors, process correlations, and queue drops before v0.2 is tagged.

## Safety ceilings

- process and socket snapshots fail closed at their configured ceilings
- filesystem traversal, including directories and discovered home paths, stops at `max_files`
- account snapshots and Windows membership edges stop at `max_accounts`
- Linux socket-owner scans stop at `max_sockets` owners and `max_fds_per_process` descriptors
- PowerShell stdout and stderr are drained concurrently with fixed capture and runtime ceilings

## Linux harness

```bash
make benchmark
```

The harness runs the release binary for 60 seconds by default and prints `/usr/bin/time -v` data. Override with `GARGOYLE_BENCHMARK_SECONDS`.

## Windows procedure

Run the release build with the sample configuration, then sample the process:

```powershell
Get-Process gargoyle | Select-Object CPU,WorkingSet64,PrivateMemorySize64,HandleCount
```

Also inspect `agent.heartbeat` metrics for queue drops, collector errors, and correlation count. Record CIM, NetTCPIP, Security-log, and Authenticode adapter latency; any individual PowerShell adapter invocation is terminated after 30 seconds.

## Churn tests

Before release, repeat the baseline while:

- starting and stopping short-lived processes
- opening and closing TCP/UDP endpoints
- changing a test local user/group
- generating successful and failed test authentication events

Do not perform destructive or high-volume tests on production hosts.
