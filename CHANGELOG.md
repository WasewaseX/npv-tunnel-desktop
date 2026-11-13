# Changelog

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
* CI: `master-ci` v2 (lint/security/SAST on ubuntu) + a `windows-latest` release pipeline
  that builds, tests, bundles the pinned core, emits SHA-256 checksums and publishes a
  GitHub Release.

### Known limitations
* System-proxy mode only — no TUN capture yet.
* Hysteria2 / WireGuard profiles are parsed and stored but need a future sing-box backend.
* Unsigned binaries (SmartScreen warning on first run).
