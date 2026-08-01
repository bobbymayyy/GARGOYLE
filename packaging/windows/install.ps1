[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\gargoyle.windows.toml'),

    [string]$InstallDirectory = (Join-Path $env:ProgramData 'GARGOYLE'),

    [string]$TaskName = 'GARGOYLE Agent'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session.'
}

$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
$destinationBinary = Join-Path $InstallDirectory 'gargoyle.exe'
$destinationConfig = Join-Path $InstallDirectory 'gargoyle.toml'

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
& icacls.exe $InstallDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to harden the GARGOYLE installation directory ACL.'
}

Copy-Item -LiteralPath $resolvedBinary -Destination $destinationBinary -Force
if (-not (Test-Path -LiteralPath $destinationConfig)) {
    Copy-Item -LiteralPath $resolvedConfig -Destination $destinationConfig
} else {
    Write-Host "Preserving existing configuration: $destinationConfig"
}

& $destinationBinary validate --config $destinationConfig
if ($LASTEXITCODE -ne 0) {
    throw 'GARGOYLE rejected the installed configuration.'
}

$quotedConfig = '"{0}"' -f $destinationConfig
$action = New-ScheduledTaskAction `
    -Execute $destinationBinary `
    -Argument "run --config $quotedConfig" `
    -WorkingDirectory $InstallDirectory
$trigger = New-ScheduledTaskTrigger -AtStartup
$principalSettings = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principalSettings `
    -Settings $settings `
    -Description 'GARGOYLE cross-platform security telemetry watchdog' | Out-Null

Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed and started $TaskName from $destinationBinary"
