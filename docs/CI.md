# CI and releases

## "Installing" master-ci

[`WasewaseX/master-ci`](https://github.com/WasewaseX/master-ci) is **not a package you
install**. It is a repository of reusable GitHub Actions workflows; you consume it with a
`uses:` reference from your own workflow file. That is why "did you install it completely"
has a slightly different answer than for a normal dependency — there is nothing to install,
there is a caller to write correctly.

`\.github/workflows/ci.yml` is that caller:

```yaml
jobs:
  master:
    uses: WasewaseX/master-ci/.github/workflows/master-ci.yml@v2
    with:
      profile: standard
      runs_on: ubuntu-latest
      run_csharp: true
      dotnet_version: '8.0'
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write

  codeql:
    uses: WasewaseX/master-ci/.github/workflows/codeql.yml@v2
    with:
      languages: csharp
    permissions:
      contents: read
      security-events: write
```

What that gives you, without any local tooling: stack detection (it sees the
`*.csproj` files and runs the .NET lane), formatting/analyzer gates, secret scanning,
dependency review, structural "AI-slop" checks across the repo, and CodeQL results in the
Security tab. The `v2` tag is the documented stable reference; pin it to a commit SHA if you
want immutability.

## The Windows job exists because master-ci runs on Ubuntu

`master-ci` intentionally targets free `ubuntu-latest` runners. WPF cannot be built there
(the Windows Desktop targeting pack is Windows-only in practice, and the app cannot run).
So `ci.yml` adds two small jobs of its own:

| Job | Runner | Purpose |
|---|---|---|
| `windows-build` | `windows-latest` | `dotnet test`, `dotnet build`, **plus a PE-header assertion that the produced `.exe` has subsystem 2 (`WINDOWS_GUI`)** — the automated guard against ever shipping a build that opens a console window again |
| `linux-core` | `ubuntu-latest` | builds `NpvTunnel.Core` with `-warnaserror` to keep the platform-neutral layer portable |

## Release pipeline

`.github/workflows/release.yml` runs on `v*` tags (or manually):

1. `dotnet test` — the 55-test suite must pass.
2. Two publishes: `lite` (framework-dependent, ~600 KB) and `portable` (self-contained
   single file, ~63 MB).
3. Downloads **Xray-core v26.11.9** and verifies **both** the archive digest and the
   extracted binary digest against constants committed in the workflow *and* compiled into
   the app.
4. Assembles `NpvTunnel-<ver>-win-x64.zip` and `NpvTunnel-<ver>-win-x64-portable.zip`
   (each with `core\`, docs and a `START-HERE.txt`).
5. Emits `npvtunnel-<ver>-checksums.txt` (SHA-256 of every asset).
6. Creates the GitHub Release with `gh release create --generate-notes`.

To cut a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## Local equivalent (Windows)

```powershell
pwsh scripts/build.ps1 -Version 1.0.0
```

Produces the same two archives under `release\`.
