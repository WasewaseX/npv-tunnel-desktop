# npvtunnel for Linux

This archive is the Linux build of NPV Tunnel Desktop. The Windows build is the
WPF app with the same look as the Android original; WPF does not exist on Linux,
so the Linux build ships the same engine, the same importer and the same safety
audit behind a command-line front end.

Everything in the archive is self-contained: the .NET runtime is inside the
`npvtunnel` binary and the tunnel engine is in `core/`. You do not install a
runtime, a package, or a service.

## Install

```sh
tar xzf NpvTunnel-<version>-linux-x64.tar.gz
cd NpvTunnel-<version>-linux-x64
sh install.sh
```

`sh install.sh` puts everything under `~/.local` (override with `PREFIX=`), links
`npvtunnel` into `~/.local/bin`, and registers `application/x-npvt` for `.npvt`,
`.npv` and `.npv4` files so a double-click imports a configuration the way it does
on Windows and Android.

Requirements: 64-bit Linux with glibc 2.28 or newer (`ldd --version`). Nothing
else. The `linux-arm64` archive is the same build for aarch64.

## First run

```sh
npvtunnel selftest
```

That runs eight checks on your machine: share-link parsing, an encrypted
container being decrypted, a private-endpoint configuration being refused, an
`allowInsecure` flag being stripped, the loopback-only bind, the redactor, the
engine digest, and the engine accepting a generated config. If it prints
`selftest passed`, the binary and the engine work here.

## Using channel configurations

```sh
npvtunnel import ~/Downloads/channel.npvt    # one file, ten to fifty configs
npvtunnel list                               # + clean   ! warnings   x refused
npvtunnel check 3                            # audit report + xray -test
npvtunnel connect 3                          # foreground tunnel, Ctrl+C to stop
```

`connect` prints the proxy address it opened:

```text
connected to 𝗜𝗥𝗖𝗢𝗡𝗙𝗜𝗚🦦6
  socks5 127.0.0.1:2080
  http   127.0.0.1:2081
  export  ALL_PROXY=socks5h://127.0.0.1:2080
```

Use `--socks` / `--http` to pick different ports, and export the `ALL_PROXY` line
in another terminal (or point your browser at the SOCKS address).

`npvtunnel config 3 -o proxy.json` writes the engine configuration without
starting anything, which is what you want for a systemd unit or a manual
`core/xray run -c proxy.json`.

## What it refuses, and why

Configurations from public channels are written by strangers. Before anything is
handed to the engine the profile is reviewed, and a few things are refused
outright instead of being connected:

| Refused | Reason |
| --- | --- |
| Loopback, RFC1918, CGNAT, link-local, ULA or IPv6 documentation addresses | A public config pointing inside your own network is broken at best, and an attempt to reach your router or your services at worst. |
| VLESS without TLS or REALITY to a public server | VLESS has no encryption of its own; the engine refuses this too, and running it would put the traffic on the wire in the clear. |
| REALITY without a public key, or malformed ports | The handshake cannot work, and a half-configured REALITY falls back to something weaker than intended. |

Warnings (still connectable) cover: no TLS on VMess/Trojan/Shadowsocks,
`allowInsecure` in the original config, a missing SNI, unusual ports, and
fragmentation or mux settings that the engine does not reproduce from the vendor
JSON.

## Security model

* The engine binary is checked against `core/ENGINE.sha256` before every run; a
  modified or replaced engine is not started.
* The generated engine config is created `0600` in a private temp directory
  (`/tmp/npvtunnel-*`), used for one run and deleted afterwards. Credentials are
  never written to a world-readable path.
* Inbounds bind `127.0.0.1` only. Nothing listens on your LAN, so the proxy is
  not open to other machines.
* The profile store `~/.config/npvtunnel/profiles.json` is sealed with
  AES-256-GCM under `~/.config/npvtunnel/store.key` (both `0600` in a `0700`
  directory). Back up both files together; the store cannot be opened without the
  key. This protects against a copied file or a synced folder, not against
  someone who can already read your home directory - use full-disk encryption for
  that.
* `npvtunnel list` and `show` redact credentials unless you pass `--reveal`.
* Unknown container formats (`NPVS` v5 and friends) are refused with an
  explanation rather than guessed at.

## Autostart

`~/.config/systemd/user/npvtunnel.service`:

```ini
[Unit]
Description=npvtunnel proxy

[Service]
ExecStart=%h/.local/bin/npvtunnel connect 0 --socks 2080 --http 2081
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now npvtunnel
```

## Uninstall

```sh
sh ~/.local/lib/npvtunnel/uninstall.sh          # keeps your stored profiles
sh ~/.local/lib/npvtunnel/uninstall.sh --purge   # removes them too
```

## Licence

The application is MIT, see `LICENSE`. The bundled engine is Xray-core, MPL-2.0,
see `THIRD-PARTY-NOTICES.md` and `core/LICENSE-xray.txt`. The white-box tables
used to decrypt vendor containers come from Pantegnos (MIT) and npvs (MIT).
