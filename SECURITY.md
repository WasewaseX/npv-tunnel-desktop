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
| 5 | No integrity check on the bundled core | A trojanised `xray.exe` next to the app intercepts everything | The SHA-256 of every shipped engine is compiled into the build and is the only authority (`EngineIntegrity`). A binary that does not match is not started, and a replaced `core\ENGINE.sha256` cannot overrule the pin: the pair agreeing with each other is evidence of tampering, not of trust |
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

### The name is resolved before it is trusted

A hostname in a config is not a fact, it is a promise. `EndpointResolver` resolves it
once, audits the answer, and hands the engine an address rather than a name:

* A name that resolves into loopback, RFC1918, CGNAT, link-local, ULA or the
  documentation ranges is **refused**, exactly like a literal private address. A channel
  config that points at `192.168.1.1` through DNS is doing the same thing as one that
  spells it out, and a rebinding answer with one bad record is refused rather than
  averaged.
* A healthy name is pinned: the generated config carries a `dns.hosts` entry for that one
  name, so the engine dials the address that was audited instead of asking DNS again a
  moment later. The pin lasts for the session; `PinResolvedEndpoint = false` turns it off.
* An unresolvable name is a warning, not a refusal - the network may simply be blocked -
  and the engine is left to resolve it itself.
* The window has no DNS bypass: it runs the same resolve-and-audit path as the command
  line before it writes any engine config.

## Not persisting the plaintext

The engine cannot read a profile from the encrypted store; at some point a readable
config file has to exist. It exists as briefly as possible:

* Each session gets its own directory (`runtime/session-<guid>`), created `0700` and
  restricted to the current user with an owner-only ACL on Windows.
* The file is written immediately before the engine starts, and **shredded as soon as the
  engine reports its local endpoints listening** - the engine has already read it by then.
* Shredding means overwriting with random bytes, flushing, renaming and deleting
  (`SecretShredder`), not just `File.Delete`.
* Anything left behind by a session that was killed is swept at startup
  (`SweepStaleRuntimeFiles`), and the directory itself is removed on a clean stop.
* On Linux the command line writes its config `0600` and removes it on exit, including on
  Ctrl-C.

This is a real limit, not a solved problem: while the engine is starting, the file exists
in the clear. It is closed by binding the engine's stdin or by a config over a private
pipe, which is not implemented yet.

## The engine binary

* **The pin decides.** `EngineIntegrity.Known` carries the SHA-256 of the engine for every
  shipped runtime, compiled into the assembly. `ENGINE.sha256` next to the binary is a
  cross-check for humans and for people who build their own archive; if it disagrees with
  the pin, the run is refused as tampering.
* **The window only runs the bundled engine.** A path left in an older settings file is
  logged and ignored, because the window has no way to ask a user to vouch for a binary
  they may not have chosen.
* **The command line can run another binary,** on purpose, but only after
  `--trust-engine`, and it says plainly that the pin did not cover it. A digest file beside
  a custom engine is checked but is never enough on its own.
* A build that ships a new engine must update `EngineIntegrity.Known`; the pin is part of
  the release, not a build-time side effect. `EnginePinDriftTests` compares the compiled
  pins against the Windows manifest and the Linux publish script, so the copies cannot
  drift apart and ship a binary the app would refuse to start.

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
* **The build treats warnings as errors** (`TreatWarningsAsErrors`, recommended analyzers,
  nullable enabled) and CI fails on any formatting drift (`dotnet format --verify-no-changes`),
  so a nullable or analyzer warning cannot quietly become a null dereference in a release.
* **The vendor-format test is not optional.** CI downloads a real channel container from
  the upstream project, pinned by commit and by digest, and the test fails if it is absent
  or changed; a sanitised copy of that container is committed as a fixture so the decoder
  path is covered offline too.

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
