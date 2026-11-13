#requires -Version 7.0
<#
.SYNOPSIS
    Builds the Linux (npvtunnel CLI + engine) release archive.

.DESCRIPTION
    Produces dist/NpvTunnel-<Version>-linux-<arch>.tar.gz containing a
    self-contained npvtunnel binary, the pinned Xray engine with its digest
    file, and an installer that wires up the .npvt file handler.

    The engine is downloaded from the pinned release and both the archive and
    the extracted binary are checked against known digests; a mismatch stops the
    build instead of shipping an engine nobody verified.

.EXAMPLE
    pwsh scripts/publish-linux.ps1 -Version 1.1.0 -Runtime linux-x64
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [ValidateSet('linux-x64', 'linux-arm64')][string]$Runtime = 'linux-x64',
    [string]$Configuration = 'Release',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Pinned engine: Xray-core v26.11.9, archive digest and extracted binary digest.
$engineRelease = 'v26.11.9'
$engines = @{
    'linux-x64'   = @{
        Zip      = 'Xray-linux-64.zip'
        ZipSha   = 'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82'
        BinarySha = 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'
    }
    'linux-arm64' = @{
        Zip      = 'Xray-linux-arm64-v8a.zip'
        ZipSha   = '64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be'
        BinarySha = 'c2d1e66a130556d32089adcf38202fcb6f9027e41fb456cc2cda9a5fabdc093a'
    }
}

$engine = $engines[$Runtime]
$arch = if ($Runtime -eq 'linux-x64') { 'x64' } else { 'arm64' }
$name = "NpvTunnel-$Version-linux-$arch"
$stage = "publish/$name"

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

Write-Host "==> npvtunnel $Version ($Runtime)" -ForegroundColor Cyan

if (-not $SkipTests) {
    Write-Host '==> Tests'
    dotnet test tests/NpvTunnel.Core.Tests/NpvTunnel.Core.Tests.csproj --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }

    dotnet test tests/NpvTunnel.Cli.Tests/NpvTunnel.Cli.Tests.csproj --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'CLI tests failed.' }
}

Write-Host "==> Publish ($Runtime, self-contained)"
Remove-Item "publish/$Runtime" -Recurse -Force -ErrorAction SilentlyContinue
dotnet publish src/NpvTunnel.Cli/NpvTunnel.Cli.csproj --configuration $Configuration `
    --runtime $Runtime --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=none -p:Version=$Version --output "publish/$Runtime"
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

$binary = "publish/$Runtime/npvtunnel"
if (-not (Test-Path $binary)) { throw "Publish did not produce $binary." }

# A framework-dependent build would ask the user to install .NET on first run,
# which is exactly what the release is not allowed to do.
if ((Get-Item $binary).Length -lt 20MB) {
    throw "npvtunnel is only $([math]::Round((Get-Item $binary).Length / 1MB, 1)) MB - it is not self-contained."
}

Write-Host '==> Engine'
$engineDir = "publish/engine-$Runtime"
if (-not (Test-Path "$engineDir/xray")) {
    Remove-Item $engineDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $engineDir -Force | Out-Null
    $zip = "publish/$($engine.Zip)"
    Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/download/$engineRelease/$($engine.Zip)" -OutFile $zip
    if ((Get-Sha256 $zip) -ne $engine.ZipSha) {
        throw "Engine archive digest mismatch for $($engine.Zip)."
    }

    Expand-Archive -Path $zip -DestinationPath $engineDir -Force
    Remove-Item $zip -Force
}

$engineSha = Get-Sha256 "$engineDir/xray"
if ($engineSha -ne $engine.BinarySha) {
    throw "Engine binary digest mismatch: expected $($engine.BinarySha), found $engineSha."
}

Write-Host '==> Stage'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$stage/core" -Force | Out-Null
Copy-Item $binary "$stage/npvtunnel"
Copy-Item "$engineDir/xray", "$engineDir/geoip.dat", "$engineDir/geosite.dat" "$stage/core/"
if (Test-Path "$engineDir/LICENSE") {
    Copy-Item "$engineDir/LICENSE" "$stage/core/LICENSE-xray.txt"
}
else {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/XTLS/Xray-core/$engineRelease/LICENSE" -OutFile "$stage/core/LICENSE-xray.txt"
}
"$engineSha  xray" | Out-File "$stage/core/ENGINE.sha256" -Encoding ascii -NoNewline
Add-Content "$stage/core/ENGINE.sha256" ''
Copy-Item 'scripts/linux/install.sh', 'scripts/linux/uninstall.sh', 'scripts/linux/npvtunnel-open.sh', 'docs/linux/README-linux.md' -Destination $stage
Copy-Item 'LICENSE', 'THIRD-PARTY-NOTICES.md' "$stage/"

# Archives built on Windows lose the execute bit, so set it where the filesystem
# supports it and the installer is always runnable with `sh install.sh` anyway.
if (-not $IsWindows) {
    & chmod 0755 "$stage/npvtunnel" "$stage/install.sh" "$stage/uninstall.sh" "$stage/npvtunnel-open.sh" "$stage/core/xray"
}

Write-Host '==> Archive'
New-Item -ItemType Directory 'dist' -Force | Out-Null
$tar = "dist/$name.tar.gz"
Remove-Item $tar -ErrorAction SilentlyContinue
tar -czf $tar -C publish $name
if ($LASTEXITCODE -ne 0) { throw 'tar failed.' }

if (-not (Test-Path $tar) -or (Get-Item $tar).Length -lt 20MB) {
    throw "Archive $tar is missing or too small to be a self-contained build."
}

$sha = Get-Sha256 $tar
Write-Host "==> $tar ($([math]::Round((Get-Item $tar).Length / 1MB, 1)) MB)"
Write-Host "    sha256 $sha"
"$sha  $name.tar.gz" | Out-File "dist/$name.sha256" -Encoding ascii -NoNewline
Add-Content "dist/$name.sha256" ''
