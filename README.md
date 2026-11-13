# NPV Tunnel Desktop

[![CI](https://github.com/WasewaseX/npv-tunnel-desktop/actions/workflows/ci.yml/badge.svg)](https://github.com/WasewaseX/npv-tunnel-desktop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/WasewaseX/npv-tunnel-desktop)](https://github.com/WasewaseX/npv-tunnel-desktop/releases/latest)

A native Windows client for **NPV Tunnel / NapsternetV** configuration files — same
profiles, same share links, none of the mobile-app baggage.

Built as a WPF desktop application with a hidden, hash-pinned tunnel core. No console
window, no Electron, no browser engine, no telemetry.

> **Author:** WasewaseX · **License:** MIT · **Platform:** Windows 10 / 11 (x64)

---

## What it does

| | |
|---|---|
| **Native GUI** | WPF, dark UI, custom window chrome. Ships as a GUI-subsystem binary — nothing ever opens a terminal window. |
| **.npvt everywhere** | Double-click a `.npvt` in Explorer, drag one onto the window, import from the file dialog, or paste a share link. Registered per-user under `HKCU\Software\Classes` (no admin, fully reversible). |
| **Real tunnel** | VLESS (incl. REALITY), VMess, Trojan, Shadowsocks, SOCKS5 and HTTP outbounds via a pinned Xray-core. TCP / WS / gRPC / HTTPUpgrade / XHTTP / QUIC transports. |
| **Leak protection** | IPv6 blackhole, QUIC block, LAN bypass, DNS-over-HTTPS through the tunnel, and proxy teardown on every exit path. |
| **Local proxy** | SOCKS5 + HTTP on loopback, bound to `127.0.0.1` only. |
| **Secret storage** | Profiles encrypted at rest with Windows DPAPI (`CurrentUser`). Nothing readable in `%LOCALAPPDATA%` if the disk is stolen. |
| **Live telemetry** | Uptime, TCP ping, and real throughput read from the core's own I/O counters — not guesswork. |
| **Redacted logs** | Every log line is scrubbed of UUIDs, passwords, keys and share links before it is displayed, copied or written. |

## Install

**Recommended — the installer** (`NpvTunnel-1.0.1-win-x64-setup.exe`):

1. Run it. Windows shows one SmartScreen prompt ("More info → Run anyway") because the
   binary is not code-signed — signing certificates cost money, and this project has none.
2. There is **no UAC prompt**: Setup installs into `%LOCALAPPDATA%\Programs\NPV Tunnel`.
3. It registers the `.npvt` association for your user, so after setup you can **double-click
   any `.npvt` file and it imports straight into the app** — the same one-tap flow the
   Android app gives you with an `.npv` file.

Portable alternatives, if you would rather not install anything:

| Archive | Size | Needs |
|---|---|---|
| `NpvTunnel-1.0.1-win-x64-portable.zip` | ~66 MB | nothing — self-contained single file |
| `NpvTunnel-1.0.1-win-x64-lite.zip` | ~2 MB + engine | the **.NET 8 Desktop Runtime** — if Windows offers to send you to a download page, you have the lite build; take the setup or the portable zip instead |

Every release ships `npvtunnel-1.0.1-checksums.txt` (SHA-256) next to the binaries, and the
bundled `core\xray.exe` is pinned by digest at build time.

### First run

1. Import a profile: double-click a `.npvt`, drag it onto the window, press the `+` button,
   or paste a share link from the clipboard.
2. Pick the server, press **CONNECT**.
3. The Windows system proxy is set while the tunnel is up and restored on disconnect, on
   exit, and after a crash — a stale proxy is detected and repaired on the next start.

## File formats

* **`.npvt` (npvt/1)** — the open, documented JSON schema this app speaks. See
  [docs/NPVT-FORMAT.md](docs/NPVT-FORMAT.md). Includes an optional AES-256-GCM "locked"
  envelope so providers can hand out configs users cannot read or reshare.
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
dotnet test          # 82 tests: parsers, importer, locked envelope, config builder, redaction, validators
```

The engine configuration builder is covered by tests that assert on the generated JSON —
including that inbounds can only bind to loopback and that IPv6/QUIC leak rules are present.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model and the specific defects this port
fixes. Short version:

* imports are treated as hostile input (size, depth, duplicate-key and field validation);
* the tunnel core is verified against a SHA-256 pin before every exec;
* the UI never runs with admin rights and never writes a machine-wide setting;
* no secret is ever written to disk in the clear, and no log line leaves unredacted.

## Roadmap

* TUN / system-wide capture via Wintun (needs a signed driver — deliberately out of scope for 1.0)
* sing-box backend for Hysteria2 / WireGuard
* Tray icon, per-app split tunneling, subscription auto-update
* Code-signed installers

## Third-party

Xray-core (MPL-2.0) is bundled as a separate executable and is downloaded in CI with a
digest check. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
