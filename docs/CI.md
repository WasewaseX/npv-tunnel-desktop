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
| `deps-review` | Dependency review on pull requests |
| `scorecard` | OSSF Scorecard published to the Security tab |

Only those jobs are selected. The template's style-scoring jobs (a vocabulary and
"AI-text" scorer with a numeric ceiling) are not part of this project's gate: a
score about how prose or identifiers read does not catch a bug, and it makes a
build fail for reasons a contributor cannot act on.

The core was recovered from the shipped 1.0.0 binaries, so its baseline
complexity is whatever the decompiler produced. Nothing here is enforced through a
score; the analyzers report, and the tests decide.

## The Windows job

`windows` builds the real WPF application on `windows-latest` and then
asserts the two things that define this project's behaviour:

1. **GUI subsystem.** `e_lfanew` at `0x3C`, `Subsystem` (a `UInt16`) at `PE + 0x5C`
   must be `2` (`WINDOWS_GUI`). `3` would mean a console window is allocated on
   start, which is exactly the defect this port exists to remove.
2. **No console host.** Greps the GUI project for `AllocConsole` / `kernel32`
   console P/Invokes.

It also publishes `win-x64` so a broken runtime identifier or a missing resource
fails in CI rather than in a release, and runs `--selftest` over **both** palettes:
a theme that only fails when the user selects it is exactly the breakage CI should
have caught.

## The Linux job

`linux` runs on `ubuntu-latest` and covers the build that is not a WPF app:

1. `dotnet test` over both suites (core + CLI).
2. `scripts/check-themes.ps1` - both palettes define the same keys and every
   `StaticResource` a view asks for resolves; then the light theme is regenerated
   and the working tree must stay clean, so a hand edit cannot drift.
3. `scripts/publish-linux.ps1` publishes the self-contained single file, downloads
   the pinned engine, verifies the archive **and** extracted binary digests, and
   builds the `.tar.gz`.
4. The archive is unpacked, `install.sh` is run under `env -i` (no `DOTNET_ROOT`,
   no runtime on `PATH`), and `npvtunnel selftest`, `import`, `list`, `check` and
   `show` are exercised against the installed copy. `show` must redact the UUID.
5. The store must be sealed: `profiles.json` cannot contain an address from the
   configuration in the clear, and both files must be `0600`.

## Releases (`.github/workflows/release.yml`)

Pushing a tag `v*` (or running the workflow manually) does this on
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

Then the `linux` job runs on `ubuntu-latest` once the release exists: it builds
both architectures with `scripts/publish-linux.ps1`, runs the x64 archive the same
way the `linux` CI job does, and uploads the two `.tar.gz` files plus their
`.sha256` files to the same release.

No untrusted value is interpolated into a script body: versions reach the steps
through `env`, which is what the template-injection audit requires.

## Reproducing the release locally (optional, Windows only)

```powershell
pwsh scripts/build.ps1 -Version 1.0.0
iscc "/DMyAppVersion=1.0.0" installer\NpvTunnel.iss
```

The repository never contains binaries: `core\` is fetched and verified at build
time, and `dist\` plus `publish\` are ignored.

## What the pipeline refuses to skip

* **Warnings.** `Directory.Build.props` sets `TreatWarningsAsErrors` and turns on the
  recommended analyzer set, so nullable warnings and analysis findings fail the build.
  A handful of stylistic rules (CA1507, CA1707, CA1822, CA1001, CA1845) are switched off in
  `.editorconfig` with a comment each; nothing in the security or reliability band is.
* **Formatting.** `dotnet format NpvTunnel.sln --verify-no-changes` runs before the tests.
* **Pin drift.** The engine digest is written down in three places - the pins compiled
  into the build, the Windows manifest and the Linux publish script - and
  `EnginePinDriftTests` compares all three, so a release cannot ship a binary that the
  application would then refuse to start.
* **The vendor sample.** Both the Windows and the Linux job download the upstream npvs
  test container by commit and verify its SHA-256, then export `NPVT_REAL_SAMPLE`. The test
  that reads it is a `SkippableFact`: skipped locally when the variable is absent, but a
  hard failure in CI if the download or the digest is wrong.
