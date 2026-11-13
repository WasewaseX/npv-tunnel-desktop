# CI and releases

Everything is built and verified on GitHub Actions. There is no local Windows
requirement: the WPF project sets `EnableWindowsTargeting=true`, so the shared
quality pipeline runs on `ubuntu-latest` and the GUI binary is still produced and
checked.

## The quality pipeline (`.github/workflows/ci.yml`)

`master-ci` at [`WasewaseX/master-ci`](https://github.com/WasewaseX/master-ci) is a
repository of reusable workflows, not a package. Consuming it means writing one
`uses:` caller, and pinning it to a commit so a moved tag cannot change what runs
in this repository:

```yaml
jobs:
  master:
    uses: WasewaseX/master-ci/.github/workflows/master-ci.yml@53e85397bc2f1d097d1665e8976873f1adfdc439 # v2.12.0
    with:
      profile: standard
      runs_on: ubuntu-latest
      run_csharp: 'true'
      dotnet_version: '8.0.x'
      template_ref: 'v2.12.0'
```

What that buys, per push and per pull request:

| Gate | What it does here |
|---|---|
| `csharp` | `dotnet build -c Release` + `dotnet test` over the whole solution, with the .NET analyzers at `latest` |
| `security` | CodeQL-style SAST and dependency review over the tree |
| `secrets` | Secret scanning on every commit |
| `hygiene` | `.editorconfig` conformance, `actionlint` and `zizmor` over the workflows, duplication threshold |
| `ai-integrity` | Blocking-score ceiling plus the new-code gates: added lines must have zero blocking findings and cognitive/cyclomatic complexity <= 15 |
| `quality-ratchet`, `new-code-gate` | The trend files that stop quality from sliding back |
| `scorecard` | OSSF Scorecard published to the Security tab |

The core was recovered from the shipped 1.0.0 binaries, so its baseline
complexity is whatever the decompiler produced. That baseline is recorded as the
ceiling in `ci.yml`; the **new-code** gates are the ones that matter going
forward, and every line added from here on has to clear them.

## The Windows smoke job

`windows-smoke` builds the real WPF application on `windows-latest` and then
asserts the two things that define this project's behaviour:

1. **GUI subsystem.** `e_lfanew` at `0x3C`, `Subsystem` (a `UInt16`) at `PE + 0x5C`
   must be `2` (`WINDOWS_GUI`). `3` would mean a console window is allocated on
   start, which is exactly the defect this port exists to remove.
2. **No console host.** Greps the GUI project for `AllocConsole` / `kernel32`
   console P/Invokes.

It also publishes `win-x64` so a broken runtime identifier or a missing resource
fails in CI rather than in a release.

## Releases (`.github/workflows/release.yml`)

Pushing a tag `v*` (or running the workflow manually) does all of this on
`windows-latest`:

1. `scripts/build.ps1` publishes the framework-dependent (lite) and
   self-contained single-file (portable) builds, downloads the pinned Xray-core
   archive, verifies **both** its SHA-256 and the extracted `xray.exe` digest,
   then stages and zips both flavours.
2. Inno Setup compiles `installer/NpvTunnel.iss` into
   `NpvTunnel-<version>-win-x64-setup.exe` - per user, no UAC, with the `.npvt`
   association.
3. A SHA-256 manifest is written for every artifact.
4. The GitHub Release is created (or updated) with the three downloads, the
   manifest and generated notes.

No untrusted value is interpolated into a script body: versions reach the steps
through `env`, which is what the template-injection audit requires.

## Reproducing the release locally (optional, Windows only)

```powershell
pwsh scripts/build.ps1 -Version 1.0.0
iscc "/DMyAppVersion=1.0.0" installer\NpvTunnel.iss
```

The repository never contains binaries: `core\` is fetched and verified at build
time, and `dist\` plus `publish\` are ignored.
