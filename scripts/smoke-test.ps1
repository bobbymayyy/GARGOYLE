[CmdletBinding()]
param(
    [string]$Binary = '.\target\release\gargoyle.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("gargoyle-smoke-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $config = Join-Path $temporary 'gargoyle.toml'
    & $Binary print-default-config | Set-Content -LiteralPath $config -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'print-default-config failed' }

    & $Binary validate --config $config
    if ($LASTEXITCODE -ne 0) { throw 'configuration validation failed' }

    $schema = & $Binary print-event-schema | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'print-event-schema failed' }
    if ($schema.title -ne 'GARGOYLE Event v2') { throw 'unexpected event schema title' }

    Write-Host 'GARGOYLE Windows smoke test passed'
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
