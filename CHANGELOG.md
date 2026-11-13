# Changelog

## 1.0.2 - 2026-11-13

### Fixed

* **Real .npvt files now import.** 1.0.1 only understood this project's own
  `npvt/1` JSON, so a configuration downloaded from a channel was rejected with
  "Unrecognised configuration". The vendor format is `NPVT1` plus comma-separated
  white-box AES-CTR blocks, and it is now decoded in-process: containers with a
  version chunk, a profile array and a lockConfig chunk all open, and every
  profile inside them is imported at once.
* The profile reader takes the server, port, UUID/password, transport, TLS/REALITY
  settings, path, host, SNI, fingerprint and flow from the nested Xray config that
  the container carries. Only the outbound is read - inbounds and routing rules in
  a hostile file are ignored rather than executed.
* `.npvs` containers are recognised and explained honestly (passphrase or app key
  the author holds) instead of being reported as garbage.
* A configuration that asks to skip TLS verification still cannot turn that on;
  the request is ignored and logged.

### Changed

* **The window now mirrors the Android layout**: centred wordmark and version,
  the Last ping / Ping row, Smart Route, the Saved group with its collapsible
  list, Global Network with the teal-to-mint session bar, the floating action
  pill, and the four-item bottom navigation (Home, Configs, Logs, More) with the
  pill indicator under the active tab.
* Home is the phone's Home: power ring, `[ STATUS ]` bracket, active connection
  card with downlink/uplink, live rates underneath.
* Search moved into the action pill, exactly where the phone keeps it.

### Added

* Nine tests for the container path, including the cipher's published
  known-answer vector and a round-trip through real container layout.

## 1.0.1 - 2026-11-13

### Fixed

* **Crash on launch (1.0.0).** `InvariantGlobalization=true` in
  `Directory.Build.props` made WPF throw
  `Cannot find non-neutral culture related to 'en-us'` while rendering the first
  window, so both the installer and the portable build closed immediately with an
  error box. Invariant mode is off, and three tests plus a workflow check now pin
  it so it cannot come back.
* The crash dialog now prints the log directory instead of pointing at a log view
  the user cannot reach when startup fails.

### Added

* `--selftest` switch: runs the production startup path (resources, services, view
  models, window creation, first render) and exits with a status code. CI executes
  it against the published binary, so "the app starts" is now a tested fact.
* `scripts/build.ps1` refuses to package a portable build under 30 MB (not really
  self-contained) or any build whose runtime config enables invariant
  globalization.
* Release notes state plainly which download needs the .NET 8 Desktop Runtime.

## 1.0.0 — 2026-11-12

First Windows release.

### Added

* Native WPF desktop UI (dark theme, custom chrome, no console window).
* Dashboard with circular connect control, live uptime / ping / throughput.
* Server library with search, ping-all, per-server connect and removal.
* Import from `.npvt`, share links (`vless`, `vmess`, `trojan`, `ss`, `socks`, `http`,
  `hysteria2`), clipboard, file dialog and drag &amp; drop.
* Export to `npvt/1`, optionally locked with AES-256-GCM.
* Per-user `.npvt` file association; double-click opens the profile in the running window.
* DPAPI-encrypted profile store, redacted logs, secure deletion of runtime configs.
* Xray-core supervisor: hash-pinned engine, hidden child process, readiness probe,
  automatic reconnect, I/O-counter traffic stats.
* System proxy integration with snapshot/restore and crash recovery.
* Leak protection: IPv6 blackhole, QUIC block, LAN bypass, DoH through the tunnel.
* Settings: ports, DNS, routing toggles, start with Windows, engine install, association
  toggle, proxy restore, data folder.
* Per-user Inno Setup installer (`NpvTunnel-1.0.0-win-x64-setup.exe`): no UAC, one
  SmartScreen prompt, registers the `.npvt` association (incl. Default Programs) and
  ships the tunnel core inside the package so the first connection works offline.
* 79 unit tests over the parser, importer, locked envelope, engine-config builder,
  redaction and validators.
* CI: `master-ci` v2 (lint/security/SAST on ubuntu) + a `windows-latest` release pipeline
  that builds, tests, bundles the pinned core, emits SHA-256 checksums and publishes a
  GitHub Release.

### Known limitations

* System-proxy mode only — no TUN capture yet.
* Hysteria2 / WireGuard profiles are parsed and stored but need a future sing-box backend.
* Unsigned binaries (SmartScreen warning on first run).
