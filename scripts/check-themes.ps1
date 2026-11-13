#requires -Version 7.0
<#
.SYNOPSIS
    Checks that the two palettes define the same keys and that every resource the
    XAML asks for actually exists.

.DESCRIPTION
    WPF resolves StaticResource when the dictionary loads, so a key that only
    exists in the dark theme fails at runtime, on the user's machine, when they
    switch to the light one. This runs in CI on every push instead.

.EXAMPLE
    pwsh scripts/check-themes.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$themeDir = Join-Path $root 'src/NpvTunnel.App/Themes'

function Get-Keys([string]$Path) {
    $text = Get-Content -Path $Path -Raw
    $keys = [regex]::Matches($text, 'x:Key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
    return @($keys | Sort-Object -Unique)
}

function Get-References([string]$Path) {
    $text = Get-Content -Path $Path -Raw
    $refs = [regex]::Matches($text, '\{(?:Static|Dynamic)Resource\s+(?:ResourceKey=)?([A-Za-z0-9_.]+)\s*\}') |
        ForEach-Object { $_.Groups[1].Value }
    return @($refs | Sort-Object -Unique)
}

$dark = Get-Keys (Join-Path $themeDir 'Theme.xaml')
$light = Get-Keys (Join-Path $themeDir 'Theme.Light.xaml')

$problems = @()

$onlyDark = Compare-Object -ReferenceObject $dark -DifferenceObject $light | Where-Object SideIndicator -eq '<='
$onlyLight = Compare-Object -ReferenceObject $dark -DifferenceObject $light | Where-Object SideIndicator -eq '=>'
foreach ($entry in $onlyDark) { $problems += "missing from Theme.Light.xaml: $($entry.InputObject)" }
foreach ($entry in $onlyLight) { $problems += "missing from Theme.xaml: $($entry.InputObject)" }

# Anything the views, the shell or the themes reference has to exist in both.
$xamlFiles = @(Get-ChildItem -Path (Join-Path $root 'src/NpvTunnel.App') -Recurse -Filter '*.xaml' |
    Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' })

# App-level keys that do not live in a theme dictionary.
$declaredElsewhere = @('BoolToVis')
foreach ($file in $xamlFiles) {
    # A view may define its own local resources; those resolve without a theme.
    $local = Get-Keys $file.FullName
    foreach ($key in (Get-References $file.FullName)) {
        if ($declaredElsewhere -contains $key) { continue }
        if ($local -contains $key) { continue }
        if ($dark -notcontains $key) {
            $problems += "$($file.Name) references '$key', which neither theme defines"
        }
    }
}

if ($problems.Count -gt 0) {
    $problems | Sort-Object -Unique | ForEach-Object { Write-Host "::error::$_" }
    throw "Theme consistency check failed with $($problems.Count) problem(s)."
}

Write-Host "Themes agree: $($dark.Count) keys in both, every reference resolves."
