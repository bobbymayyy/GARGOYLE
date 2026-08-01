# Windows Operations

## Supported surfaces

GARGOYLE v0.2 uses Windows-provided management surfaces rather than project-owned unsafe FFI:

- CIM `Win32_Process`
- NetTCPIP TCP/UDP endpoint cmdlets
- CIM local user/group classes and `Win32_GroupUser` membership associations
- Security Event Log through `Get-WinEvent`
- Authenticode inspection

Run as Administrator or SYSTEM for consistent access.

## Adapter safety boundaries

PowerShell is used only for fixed, project-owned collector programs. GARGOYLE drains stdout and stderr concurrently into bounded buffers, rejects output above the configured internal ceiling, and terminates an adapter invocation after 30 seconds. Process, socket, account, and group-member inventories use probe limits and fail the poll rather than returning partial state.

## Audit policy

GARGOYLE does not modify audit policy automatically. Enable only the categories appropriate to the host's security and privacy requirements. Typical elevated commands are:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Event 4688 command-line content additionally depends on the Windows policy **Include command line in process creation events**. GARGOYLE still suppresses that field unless `collectors.process.capture_command_line` is enabled and applies `max_command_line_bytes` before emitting it. Command lines can expose secrets, so leave both controls disabled unless their investigative value is justified.

## Security Event IDs

Default normalization:

- 4624 successful logon
- 4625 failed logon
- 4648 explicit credentials
- 4672 special privileges assigned to a new logon
- 4688 process creation

The configured list is strict and bounded. Unknown event IDs are ignored until a normalizer is implemented.
The cursor detects record-ID rollback after the Security log is cleared or recreated and resumes from the new log generation.

## Installation

Build the release binary, then run elevated:

```powershell
.\packaging\windows\install.ps1 `
  -BinaryPath .\target\release\gargoyle.exe `
  -ConfigPath .\config\gargoyle.windows.toml
```

Installed layout:

```text
C:\ProgramData\GARGOYLE\
  gargoyle.exe
  gargoyle.toml
  events.jsonl
```

The installer preserves an existing config, validates it, restricts ACL inheritance, registers `GARGOYLE Agent` as a SYSTEM startup task, and starts it.

## Validation and troubleshooting

```powershell
& 'C:\ProgramData\GARGOYLE\gargoyle.exe' validate `
  --config 'C:\ProgramData\GARGOYLE\gargoyle.toml'

Get-ScheduledTask -TaskName 'GARGOYLE Agent'
Get-ScheduledTaskInfo -TaskName 'GARGOYLE Agent'
Get-Content 'C:\ProgramData\GARGOYLE\events.jsonl' -Tail 20
```

A recurring `collector.error` from the auth collector usually means Security-log access or audit configuration is missing. Process, network, or identity errors can also indicate a provider timeout or configured snapshot ceiling; GARGOYLE preserves the previous snapshot in that case. Fingerprint errors are attached to process events rather than suppressing them.

## Uninstall

```powershell
.\packaging\windows\uninstall.ps1
```

Configuration and event data are preserved unless `-RemoveConfiguration` is supplied.
