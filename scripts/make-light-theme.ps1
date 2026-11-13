#requires -Version 7.0
<#
.SYNOPSIS
    Regenerates Themes/Theme.Light.xaml from Themes/Theme.xaml.

.DESCRIPTION
    The two themes share one set of styles and templates; only the palette
    differs. This script rewrites every colour literal through the map below, so
    the light theme can never drift away from the dark one when a style changes.

    The light palette is warm paper, not white: a #FFFFFF canvas is exactly the
    glare this mode exists to avoid. Surfaces sit between #F5EFE3 and #FBF6EC,
    ink is #2B2721, and the accent keeps the same emerald identity, darkened
    enough to stay legible on paper.

.EXAMPLE
    pwsh scripts/make-light-theme.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'src/NpvTunnel.App/Themes/Theme.xaml'
$target = Join-Path $root 'src/NpvTunnel.App/Themes/Theme.Light.xaml'

# dark -> warm light. Every entry is a deliberate choice, not an inversion:
# a straight inversion of a green-black palette produces a harsh blue-white.
$map = [ordered]@{
    '#FF060C09' = '#FFEDE4D3'   # deep canvas
    '#FF08100C' = '#FFF7F1E5'   # background gradient start
    '#FF070E0B' = '#FFF2EADC'   # background gradient end
    '#FF0A120E' = '#FFF5EFE3'   # canvas
    '#FF0B110E' = '#FFF8F3E8'   # bottom bar
    '#FF0C1511' = '#FFE6DCC7'   # button pressed
    '#FF0E1512' = '#FFFBF6EC'   # row
    '#FF0F1714' = '#FFFBF6EC'   # card
    '#FF10312A' = '#FFE4EFE7'   # nav pill
    '#FF122019' = '#FFF6EFE1'   # card alt / tile
    '#FF12301F' = '#FFEDE6D6'   # pill background
    '#FF132C20' = '#FFE7EFE4'   # active row
    '#FF161D19' = '#FFF3ECDE'   # group row
    '#FF16211B' = '#FFE4DBC8'   # toggle track
    '#FF16321F' = '#FFE8F0E4'   # tinted row
    '#FF1A2A22' = '#FFEDE5D6'   # button hover
    '#FF1E2A24' = '#FFDED3BF'   # hairline stroke
    '#FF234A35' = '#FFD7CBB4'   # pill stroke
    '#FF2A0E13' = '#FFF1DCDA'   # danger hover
    '#FF2C4038' = '#FFC9BCA4'   # bright stroke
    '#FF2C6B45' = '#FFA9C3B0'   # tinted row stroke
    '#FF3FE58F' = '#FF1F7A52'   # accent (emerald, darkened for paper)
    '#FF55EEA0' = '#FF2A8F62'   # accent hover
    '#FF1EC7A8' = '#FF177F76'   # accent deep (teal)
    '#FF2ECF80' = '#FF1A6C49'   # accent pressed
    '#FF37D6C9' = '#FF177F76'   # teal
    '#FFE9B44C' = '#FFC98B2B'   # amber
    '#FFFF5C6C' = '#FFB4434F'   # danger
    '#FFE81123' = '#FFB4434F'   # window close
    '#FFE8F1EC' = '#FF2B2721'   # ink
    '#FF7E8F86' = '#FF6E655A'   # muted ink
    '#FF6E7F76' = '#FF8A8071'   # toggle knob
    '#FF04241B' = '#FFFFF8EC'   # label on accent
    '#22FFFFFF' = '#3A8A7A62'   # scroll thumb
    '#0AFFFFFF' = '#FFEDE5D6'   # faint fill
    '#08FFFFFF' = '#FFF1EADD'   # list hover
    '#143FE58F' = '#141F7A52'   # hero glow
    '#FFFFF6EC' = '#FFFFF8EC'   # label on danger
}

if (-not (Test-Path $source)) { throw "Missing $source" }

$text = Get-Content -Path $source -Raw

# Longest literals first so a 8-digit colour is never clipped by a 6-digit match.
foreach ($hex in ($map.Keys | Sort-Object Length -Descending)) {
    $text = $text.Replace($hex, $map[$hex])
}

$banner = @'
<!--
    GENERATED FILE - do not edit by hand.
    Produced by scripts/make-light-theme.ps1 from Themes/Theme.xaml.
    Same styles, warm paper palette: no white surfaces anywhere.
-->
'@

# The palette description in the header has to describe this palette, not the dark one.
$lightNote = @'
    <!-- =====================================================================
        Warm paper palette: cream surfaces (#F5EFE3 to #FBF6EC), brown-black ink
        (#2B2721), the same emerald and teal accents darkened so they hold their
        contrast on paper. No pure white anywhere - the point of this mode is to
        stop a bright canvas from hurting the eyes at night.
        ===================================================================== -->
'@
$text = $text -replace '(?s)    <!-- =+\r?\n\s*Palette taken from the NPV Tunnel design language.*?=+ -->', $lightNote.TrimEnd()

$output = $text -replace '(?s)^(<ResourceDictionary[^>]*>\s*)', ('$1' + $banner + [Environment]::NewLine)

# The repository is checked out with LF (see .gitattributes) and this script is
# stored with CRLF, so the here-string literals it splices in are normalised here.
$output = $output -replace "`r`n", "`n"
Set-Content -Path $target -Value $output -Encoding utf8 -NoNewline

$remainingWhite = Select-String -Path $target -Pattern '#FFFFFFFF|#FFFFFF(?![0-9A-Fa-f])|"White"' -AllMatches
if ($remainingWhite) {
    $remainingWhite | ForEach-Object { Write-Host "pure white found: $($_.Line.Trim())" }
    throw 'The light theme contains pure white; the palette map needs another entry.'
}

Write-Host "Wrote $target"
Write-Host ("Mapped {0} colours." -f $map.Count)
