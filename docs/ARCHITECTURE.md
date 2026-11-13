# Architecture

```
┌────────────────────────────── NpvTunnel.exe (WinExe, no console) ─────────────────────────────┐
│  WPF shell (MainWindow + 4 views)                                                             │
│      │ data binding                                                                           │
│  MainViewModel ── orchestrates connect / disconnect / import / settings                       │
│      │                                                                                        │
│      ├── ProfileRepository ── DPAPI-encrypted profiles.dat (%LOCALAPPDATA%\NpvTunnel)          │
│      ├── LogService ───────── redacted ring buffer + rotating file                            │
│      ├── SystemProxyService ─ HKCU WinINET proxy + snapshot/restore                           │
│      ├── FileAssociationService ─ HKCU\Software\Classes\.npvt                                 │
│      ├── SingleInstance ───── mutex + CurrentUserOnly named pipe (second launch forwarding)    │
│      └── EngineManager ────── starts/ supervises the core, reads I/O counters                 │
│                                   │                                                           │
└───────────────────────────────────┼───────────────────────────────────────────────────────────┘
                                    │ ArgumentList: run -c <tmp config>, CreateNoWindow
                                    ▼
                        core\xray.exe  (hash-pinned, hidden child process)
                          ├── 127.0.0.1:2080 SOCKS5
                          └── 127.0.0.1:2081 HTTP  ──►  proxy outbound ──►  your server
```

## Layers

| Project | TFM | Contents |
|---|---|---|
| `src/NpvTunnel.Core` | `net8.0` | Models, share-link parser, `npvt/1` importer, locked-config crypto, validators, redactor, Xray config builder. **No Windows APIs** — fully unit-testable anywhere. |
| `src/NpvTunnel.App` | `net8.0-windows` | WPF UI, DPAPI store, registry integration, engine supervisor, WinINET proxy. |
| `tests/NpvTunnel.Core.Tests` | `net8.0` | xUnit suite for every parser/validator/builder path. |

Keeping Windows code out of the core is what lets `master-ci` lint and test the project on
free `ubuntu-latest` runners.

## Connection lifecycle

1. `MainViewModel.ConnectAsync()` resolves the profile from the encrypted store.
2. `XrayConfigBuilder.Build(profile, options)` produces the core config. Only an allowlist
   of fields is emitted; inbounds are loopback-only; IPv6/QUIC/LAN rules are injected.
3. `EngineManager.StartAsync()`:
   * resolves `core\xray.exe`, verifies its SHA-256 against the compiled-in pin;
   * writes the config to `%LOCALAPPDATA%\NpvTunnel\runtime\config-<rand>.json`;
   * starts it hidden with redirected pipes (no console flash), pumps stdout/stderr into
     `LogService`;
   * polls the SOCKS port until it accepts a connection (12 s budget) before reporting
     success.
4. On success the system proxy is applied (if enabled) and the 1 Hz timer starts.
5. `DisconnectAsync()` kills the process tree, restores the proxy, securely deletes the
   runtime config (overwrite + unlink) and zeroes the counters.
6. Unexpected exit → `CoreExited` → proxy restored, UI moved to *Connection failed*, up to
   three automatic reconnects.

## Why a child process instead of hosting the protocol stack in-proc

* a malformed server response kills the core, not the window;
* the core is a known upstream binary that can be hash-verified and updated independently;
* the UI stays small and has no networking attack surface of its own;
* the boundary makes "what can a config do" answerable: it can shape one outbound.

## Threading

* WPF runs the UI thread; all `ViewModel` mutations from timers/pipes are marshalled with
  `Dispatcher.BeginInvoke`.
* `PingService` and `EngineInstaller` are async and never block the UI thread.
* `LogService` is thread-safe (single lock) and is the only component written from the
  process pump threads.
