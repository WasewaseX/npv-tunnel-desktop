# NPV Tunnel Desktop

[![CI](https://github.com/WasewaseX/npv-tunnel-desktop/actions/workflows/ci.yml/badge.svg)](https://github.com/WasewaseX/npv-tunnel-desktop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/WasewaseX/npv-tunnel-desktop)](https://github.com/WasewaseX/npv-tunnel-desktop/releases/latest)

A native client for **NPV Tunnel / NapsternetV** configuration files — same profiles,
same share links, none of the mobile-app baggage.

Windows is a WPF application with a hidden, hash-pinned tunnel core; Linux is the same
importer, safety audit and engine behind `npvtunnel`. No console window on Windows, no
Electron, no browser engine, no telemetry.

> **Author:** WasewaseX · **License:** MIT · **Platforms:** Windows 10 / 11 (x64), Linux (x64, arm64)

---

## What it does

| | |
|---|---|
| **Native GUI** | WPF, custom window chrome, dark by default with a warm light mode. Ships as a GUI-subsystem binary — nothing ever opens a terminal window. |
| **.npvt everywhere** | Double-click a real channel `.npvt` in Explorer, drag one onto the window, import from the file dialog, or paste a share link. Registered per-user under `HKCU\Software\Classes` (no admin, fully reversible). |
| **Real tunnel** | VLESS (incl. REALITY), VMess, Trojan, Shadowsocks, SOCKS5 and HTTP outbounds via a pinned Xray-core. TCP / WS / gRPC / HTTPUpgrade / XHTTP / QUIC transports. |
| **Leak protection** | IPv6 blackhole, QUIC block, LAN bypass, DNS-over-HTTPS through the tunnel, and proxy teardown on every exit path. |
| **Local proxy** | SOCKS5 + HTTP on loopback, bound to `127.0.0.1` only. |
| **Secret storage** | Profiles encrypted at rest with Windows DPAPI (`CurrentUser`). Nothing readable in `%LOCALAPPDATA%` if the disk is stolen. |
| **Live telemetry** | Uptime, TCP ping, and real throughput read from the core's own I/O counters — not guesswork. |
| **Redacted logs** | Every log line is scrubbed of UUIDs, passwords, keys and share links before it is displayed, copied or written. |
| **Config review** | Every imported configuration is audited before it can connect: private/loopback endpoints, REALITY without a key and plaintext VLESS to a public server are refused, not connected. |

## Install

**Recommended — the installer** (`NpvTunnel-1.1.0-win-x64-setup.exe`):

1. Run it. Windows shows one SmartScreen prompt ("More info → Run anyway") because the
   binary is not code-signed — signing certificates cost money, and this project has none.
2. There is **no UAC prompt**: Setup installs into `%LOCALAPPDATA%\Programs\NPV Tunnel`.
3. It registers the `.npvt` association for your user, so after setup you can **double-click
   any `.npvt` file and it imports straight into the app** — the same one-tap flow the
   Android app gives you with an `.npv` file.

Portable alternatives, if you would rather not install anything:

| Archive | Size | Needs |
|---|---|---|
| `NpvTunnel-1.1.0-win-x64-portable.zip` | ~66 MB | nothing — self-contained single file |
| `NpvTunnel-1.1.0-win-x64-lite.zip` | ~2 MB + engine | the **.NET 8 Desktop Runtime** — if Windows offers to send you to a download page, you have the lite build; take the setup or the portable zip instead |

Every release ships `npvtunnel-1.1.0-checksums.txt` (SHA-256) next to the binaries, and the
bundled `core\xray.exe` is pinned by digest at build time.

**Linux** (`NpvTunnel-1.1.0-linux-x64.tar.gz` / `-linux-arm64.tar.gz`):

```sh
tar xzf NpvTunnel-1.1.0-linux-x64.tar.gz
cd NpvTunnel-1.1.0-linux-x64
sh install.sh                  # ~/.local, no root, registers .npvt

npvtunnel selftest             # proves the binary and the engine work here
npvtunnel import file.npvt     # or double-click the file
npvtunnel list                 # + clean   ! warnings   x refused
npvtunnel check 3              # review + engine -test
npvtunnel connect 3            # foreground tunnel on 127.0.0.1:2080
```

The archive carries its own .NET runtime and engine, so there is no runtime to
install. [docs/linux/README-linux.md](docs/linux/README-linux.md) covers autostart,
the security model and what is refused.

### First run

1. Import a profile: double-click a `.npvt`, drag it onto the window, press the `+` button,
   or paste a share link from the clipboard.
2. Pick the server, press **CONNECT**. A configuration that fails the safety review is
   listed with the reason and cannot be connected; the rules are in
   [SECURITY.md](SECURITY.md).
3. The Windows system proxy is set while the tunnel is up and restored on disconnect, on
   exit, and after a crash — a stale proxy is detected and repaired on the next start.

## File formats

* **`.npvt` (npvt/1)** — the open, documented JSON schema this app speaks. See
  [docs/NPVT-FORMAT.md](docs/NPVT-FORMAT.md). Includes an optional AES-256-GCM "locked"
  envelope so providers can hand out configs users cannot read or reshare.
* **Vendor `.npvt` containers** — the `NPVT1` files channels distribute, decoded
  in-process (white-box AES-CTR) and imported whole: every profile in the file lands
  in the library at once. `.npvs` (passphrase / app-key envelopes) is detected and
  explained instead of being silently mis-parsed.
* **Share links** — `vless://`, `vmess://`, `trojan://`, `ss://`, `socks://`, `http://`,
  `hysteria2://`.
* **Legacy `.npv` / `.npv4` / `.inpv`** — detected and explained rather than parsed. Those
  blobs are encrypted with a closed, undocumented format; importing them would mean
  shipping someone else's binary parser, so the app tells you to ask your provider for an
  open config instead.

## Build from source

```bash
git clone https://github.com/WasewaseX/npv-tunnel-desktop
cd npv-tunnel-desktop

dotnet test tests/NpvTunnel.Core.Tests/NpvTunnel.Core.Tests.csproj
dotnet publish src/NpvTunnel.App/NpvTunnel.App.csproj -c Release -r win-x64 \
  --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
```

The UI project targets `net8.0-windows`. With `EnableWindowsTargeting=true` it restores and
compiles on Linux/macOS too, which keeps CI cheap; the parser and engine-config layers are
plain `net8.0` so they are unit-tested on any runner.

## Testing

```bash
dotnet test                                            # 107 tests
pwsh scripts/check-themes.ps1                          # both palettes define what the views ask for
pwsh scripts/publish-linux.ps1 -Version 1.1.0 -SkipTests   # builds the Linux archive
```

107 tests cover the parsers, the importer, the container decryption, the safety audit, the
locked envelope, the config builder, redaction and validation.

The engine configuration builder is covered by tests that assert on the generated JSON —
including that inbounds can only bind to loopback and that IPv6/QUIC leak rules are present.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model and the specific defects this port
fixes. Short version:

* imports are treated as hostile input (size, depth, duplicate-key and field validation);
* every imported configuration is audited first: loopback/private endpoints, REALITY without
  a public key and plaintext VLESS to a public host are refused rather than dialled;
* the tunnel core is verified against a SHA-256 pin before every exec;
* the UI never runs with admin rights and never writes a machine-wide setting;
* no secret is ever written to disk in the clear, and no log line leaves unredacted.

### Light mode

Settings → **Appearance** switches to the warm palette: cream surfaces (`#F5EFE3` to
`#FBF6EC`), brown-black ink, emerald and teal darkened for paper. There is no pure white
anywhere, which is the point — a night-time session on a #FFFFFF canvas is what this mode
exists to avoid. Both palettes are generated from one style file, so every control is
styled in both.

## Roadmap

* TUN / system-wide capture via Wintun (needs a signed driver — deliberately out of scope for 1.0)
* sing-box backend for Hysteria2 / WireGuard
* Tray icon, per-app split tunneling, subscription auto-update
* Code-signed installers

## Third-party

Xray-core (MPL-2.0) is bundled as a separate executable and is downloaded in CI with a
digest check. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
