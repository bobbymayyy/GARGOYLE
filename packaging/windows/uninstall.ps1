[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallDirectory = (Join-Path $env:ProgramData 'GARGOYLE'),
    [string]$TaskName = 'GARGOYLE Agent',
    [switch]$RemoveConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstaller from an elevated PowerShell session.'
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$binary = Join-Path $InstallDirectory 'gargoyle.exe'
if (Test-Path -LiteralPath $binary) {
    Remove-Item -LiteralPath $binary -Force
}

if ($RemoveConfiguration) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "Preserved configuration and events in $InstallDirectory"
}
