# Security model

This document is deliberately blunt: it lists what the app defends against, how, and
where the limits are. If you are evaluating it for a filtered network, read the whole
thing.

## Design stance

1. **A configuration file is hostile input.** It arrives from a Telegram channel, a
   subscription URL, or an e-mail. It never gets to decide how the app behaves beyond the
   narrow set of fields the engine needs.
2. **The user is unprivileged.** No UAC prompt, no service, no driver, no machine-wide
   registry writes. Everything is per-user and reversible.
3. **Nothing sensitive is persisted in the clear**, and nothing sensitive is logged.
4. **The tunnel core is a pinned binary**, not a plugin and not downloaded-and-trusted.

## Defects fixed relative to the original NPV Tunnel client

| # | Original behaviour | Why it matters | What this app does |
|---|---|---|---|
| 1 | Logs / share dialogs print full configs (`vless://uuid@host…`) | A screenshot or a support paste leaks a working subscription | Every string that reaches the log view, the clipboard helper or the log file goes through `Redactor` — UUIDs, passwords, `pbk`/keys and share links are masked |
| 2 | Configs stored in app-private storage readable on a rooted/jailbroken device | Profile theft, resale, server abuse | Profiles are encrypted with **DPAPI (CurrentUser)**; the blob is useless on another machine or account |
| 3 | Closed, encrypted `.npv4` blobs parsed by an opaque binary parser | You cannot audit what the config does; parser bugs become memory-corruption bugs | Legacy blobs are **refused with an explanation**. The open replacement (`npvt/1`) is schema-validated JSON, and the optional lock envelope is documented AES-256-GCM + PBKDF2-SHA256 (210 000 iterations) |
| 4 | "Skip TLS verification" available from the config itself | A config author (or anyone who can modify the file) silently disables certificate checks | `allowInsecure` in an imported file is **ignored and reported as a warning**; only an explicit, clearly-labelled switch in Settings can enable it, and the app warns again at connect time |
| 5 | No integrity check on the bundled core | A trojanised `xray.exe` next to the app intercepts everything | SHA-256 pin compiled into the app + optional `core\ENGINE.sha256`; mismatch = the engine refuses to start |
| 6 | Unbounded config parsing | Tiny zip-bomb / deep-JSON configs hang or crash the client | `SafeJson`: 1 MiB cap, depth 32, 20 000 nodes, 8 KiB string cap, **duplicate keys rejected** |
| 7 | Config-supplied values reaching a shell or a file path | Argument injection, path traversal, "log to C:\Windows\…" | Core is started with `ProcessStartInfo.ArgumentList` (no shell), only an allowlisted config subset is emitted, paths validated, log sinks are not configurable at all |
| 8 | Proxy/ports open to the network | Open-relay abuse, LAN attackers pivoting through your tunnel | Inbounds bind `127.0.0.1` only; opting out is a separate switch that warns |
| 9 | IPv6 and QUIC bypass the tunnel | Real IP leaks on dual-stack and Chromium networks | IPv6 blackholed, QUIC blocked (configurable), DNS resolved over HTTPS *through* the tunnel |
| 10 | Kill/crash leaves the system proxy pointing at a dead port | Total loss of connectivity after a crash | Proxy state is snapshotted in `HKCU\Software\NpvTunnel\ProxyBackup` and restored on stop, on error, and **at next startup** if a previous session died |
| 11 | Predictable/global IPC surface | Local process can steer the client | Single-instance mutex and named pipe are namespaced by the user SID with `PipeOptions.CurrentUserOnly`; the payload is one existing file path, never a command |
| 12 | Admin installers writing `HKLM` associations | Machine-wide hijack, requires elevation, collides with user choice | Association is `HKCU\Software\Classes\.npvt` only, toggled from Settings |

## Configurations from public channels

A `.npvt` from a Telegram channel is a file written by a stranger that asks for a
tunnel to a host of their choosing. `NpvTunnel.Core.Security.ConfigAudit` reviews each
imported profile before it may connect, on both platforms:

| Refused (never reaches the engine) | Why |
|---|---|
| Loopback, RFC1918, CGNAT, link-local, IPv6 ULA or documentation addresses | A public config pointing into your own network is broken at best; at worst it is an attempt to reach your router or a service on your LAN. |
| VLESS without TLS or REALITY to a public host | VLESS has no encryption of its own. The engine refuses the combination and the traffic would be readable on the path. |
| REALITY without a public key, or a port outside 1-65535 | The handshake cannot complete, and a half-configured REALITY is weaker than the name implies. |

Warnings (connectable, reported in `npvtunnel check` and in the app): no TLS on
VMess/Trojan/Shadowsocks, `allowInsecure` in the source config, a missing SNI, unusual
ports, fragmentation, and mux settings the vendor JSON asks for that the engine does not
reproduce.

## Storage

* **Windows:** profiles are encrypted with DPAPI (`CurrentUser`); the blob is useless on
  another machine or account.
* **Linux:** `~/.config/npvtunnel/profiles.json` is sealed with AES-256-GCM under
  `store.key` beside it. Both are `0600` in a `0700` directory and written
  write-then-rename. That protects a copied file or a synced folder; it is not a
  substitute for full-disk encryption, because anyone who can read the key can read the
  store.

## Supply chain

* The engine archive is fetched from the upstream GitHub release **in CI**, verified
  against `EngineManifest.ArchiveSha256`, extracted through an allowlist (zip-slip proof),
  and the extracted binary is checked against `EngineManifest.PipelineSha256`.
* In-app "Install core" performs the same two hash checks and refuses to install anything
  that does not match. Redirects are limited to `github.com`, `objects.githubusercontent.com`
  and `release-assets.githubusercontent.com`; the download is capped at 96 MiB.
* Releases ship a `checksums.txt` (SHA-256 of every asset) so users can verify downloads
  independently.

## Threat model limits (be honest)

* **System-proxy mode is not a VPN.** Applications that ignore WinINET settings (some
  games, some CLI tools, anything using raw sockets) will not be proxied. Full capture
  needs TUN mode, which needs a signed kernel driver — planned, not shipped.
* **The tunnel is only as good as your server.** This app does not hide your traffic from
  the operator of the server you connect to.
* **No code-signing certificate yet.** SmartScreen will warn on first run. Verify the
  SHA-256 from `checksums.txt` against the published release.
* **DPAPI protects data at rest, not from malware running as you.** A process running in
  your session can ask DPAPI to decrypt the same blob.
* **A malicious config can still point you at a malicious server** — that is the nature of
  a client for user-supplied endpoints. It cannot, however, gain code execution in this app.

## Reporting

Open a private security advisory on the repository, or e-mail the author. Please do not
file public issues for memory-safety or privilege-boundary problems.
