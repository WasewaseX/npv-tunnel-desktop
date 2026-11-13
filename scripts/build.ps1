#requires -Version 7.0
<#
.SYNOPSIS
    Builds the NPV Tunnel Desktop release bundles on Windows, exactly like CI does.

.EXAMPLE
    pwsh scripts/build.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Configuration = 'Release',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$engineUrl     = 'https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-windows-64.zip'
$engineArchive = '1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d'
$engineBinary  = '1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185'

Write-Host "==> NPV Tunnel Desktop $Version" -ForegroundColor Cyan

if (-not $SkipTests) {
    Write-Host '==> Formatting'
    dotnet format NpvTunnel.sln --verify-no-changes --severity warn
    if ($LASTEXITCODE -ne 0) { throw 'Formatting drift: run dotnet format.' }

    Write-Host '==> Tests'
    dotnet test tests/NpvTunnel.Core.Tests/NpvTunnel.Core.Tests.csproj --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }
    dotnet test tests/NpvTunnel.Cli.Tests/NpvTunnel.Cli.Tests.csproj --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'CLI tests failed.' }
}

Write-Host '==> Publish (lite)'
dotnet publish src/NpvTunnel.App/NpvTunnel.App.csproj --configuration $Configuration `
    --runtime win-x64 --self-contained false -p:Version=$Version --output publish/lite
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

Write-Host '==> Publish (portable)'
dotnet publish src/NpvTunnel.App/NpvTunnel.App.csproj --configuration $Configuration `
    --runtime win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None `
    -p:Version=$Version --output publish/portable
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

# --- publish guards ---------------------------------------------------------
# The portable build must really be self-contained: a single executable over
# 30 MB. If -p:SelfContained=true ever stops taking effect, this fails instead of
# shipping a "portable" download that asks the user to install the .NET runtime.
$portableExe = Get-Item 'publish/portable/NpvTunnel.exe' -ErrorAction SilentlyContinue
if (-not $portableExe) { throw 'publish/portable/NpvTunnel.exe is missing.' }
if ($portableExe.Length -lt 30MB) {
    throw "Portable build is only $([math]::Round($portableExe.Length/1MB,1)) MB - it is not self-contained."
}

$liteExe = Get-Item 'publish/lite/NpvTunnel.exe' -ErrorAction SilentlyContinue
if (-not $liteExe) { throw 'publish/lite/NpvTunnel.exe is missing.' }
if ($liteExe.Length -gt 5MB) {
    throw "Lite build is $([math]::Round($liteExe.Length/1MB,1)) MB - it should stay small and framework-dependent."
}

# Invariant globalization breaks WPF on its first render (the 1.0.0 crash), so
# the generated runtime config is checked before anything is packaged.
foreach ($cfg in @(Get-ChildItem 'publish' -Recurse -Filter 'NpvTunnel.runtimeconfig.json')) {
    $json = Get-Content $cfg.FullName -Raw
    if ($json -match 'System\.Globalization\.Invariant"\s*:\s*true') {
        throw "Invariant globalization is enabled in $($cfg.FullName); WPF cannot run that way."
    }
}

Write-Host '==> Tunnel engine'
if (-not (Test-Path 'core/xray.exe')) {
    Invoke-WebRequest -Uri $engineUrl -OutFile engine.zip
    if ((Get-FileHash engine.zip -Algorithm SHA256).Hash.ToLower() -ne $engineArchive) {
        throw 'Engine archive digest mismatch.'
    }
    Expand-Archive engine.zip -DestinationPath engine-raw
    New-Item -ItemType Directory core -Force | Out-Null
    Copy-Item engine-raw/xray.exe, engine-raw/geoip.dat, engine-raw/geosite.dat -Destination core/
    Move-Item engine-raw/LICENSE core/LICENSE-xray.txt
}
$binary = (Get-FileHash core/xray.exe -Algorithm SHA256).Hash.ToLower()
if ($binary -ne $engineBinary) { throw "Engine binary digest mismatch: $binary" }
"$binary  xray.exe" | Out-File core/ENGINE.sha256 -Encoding ascii

Write-Host '==> Bundles'
$docs = @('LICENSE', 'README.md', 'SECURITY.md', 'THIRD-PARTY-NOTICES.md', 'CHANGELOG.md')
foreach ($flavour in @('lite', 'portable')) {
    $stage = "dist/$flavour"
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $stage -Force | Out-Null
    Copy-Item "publish/$flavour/*" -Destination $stage -Recurse
    Copy-Item core -Destination "$stage/core" -Recurse
    Copy-Item docs -Destination "$stage/docs" -Recurse
    foreach ($d in $docs) { Copy-Item $d -Destination $stage }
    Compress-Archive -Path "$stage/*" -DestinationPath "dist/NpvTunnel-$Version-win-x64-$flavour.zip" -CompressionLevel Optimal
}

Get-ChildItem dist/*.zip | ForEach-Object {
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)"
} | Out-File "dist/npvtunnel-$Version-checksums.txt" -Encoding ascii

Write-Host "==> Done. Archives in dist\" -ForegroundColor Green
Get-ChildItem dist/*.zip | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
