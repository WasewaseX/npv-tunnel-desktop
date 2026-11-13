# The `.npvt` format (schema `npvt/1`)

A `.npvt` file is either:

1. **a plain JSON document** with `"schema": "npvt/1"`, or
2. **a locked envelope** — a URL-safe base64 blob that decrypts to (1).

Both are printable text. There is no binary section, no undocumented padding and no
vendor-specific encryption.

## 1. Plain document

```json
{
  "schema": "npvt/1",
  "name": "Frankfurt",
  "protocol": "vless",
  "address": "de.example.com",
  "port": 443,
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "flow": "xtls-rprx-vision",
  "network": "tcp",
  "security": "reality",
  "sni": "www.microsoft.com",
  "fp": "chrome",
  "pbk": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
  "sid": "6ba85179e30d4fc2",
  "remarks": "Trial node, expires 2026-12-01"
}
```

### Fields

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `npvt/1`. Documents with an unknown `npvt/*` major version are rejected. |
| `name` | string | Display name. |
| `protocol` | enum | `vless`, `vmess`, `trojan`, `shadowsocks`, `socks`, `http`, `hysteria2`, `wireguard` |
| `address` | string | Hostname, IPv4 or IPv6 literal (no scheme, no path). |
| `port` | int | 1–65535 |
| `uuid` | string | VLESS / VMess |
| `password` | string | Trojan / Shadowsocks / SOCKS / HTTP |
| `username` | string | SOCKS / HTTP only |
| `method` | string | Shadowsocks cipher, e.g. `chacha20-ietf-poly1305` |
| `flow` | string | VLESS only, e.g. `xtls-rprx-vision` |
| `alterId` | int | VMess legacy, keep `0` |
| `vmessSecurity` | string | VMess `security`, default `auto` |
| `network` | enum | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `quic` |
| `path` / `host` / `serviceName` | string | Transport details |
| `alpn` | string[] | e.g. `["h2","http/1.1"]` |
| `security` | enum | `none`, `tls`, `reality` |
| `sni`, `fp`, `pbk`, `sid`, `spx` | string | TLS / REALITY parameters |
| `allowInsecure` | bool | **Ignored on import** — see SECURITY.md |
| `mux` | bool | Multiplexing |
| `fragment` | string | `packets,length,interval` e.g. `tlshello,100-200,10` (DPI resistance) |
| `domainStrategy` | string | `UseIP` (default), `UseIPv4`, `UseIP`, `AsIs` |
| `remarks` | string | Free text shown to the user. Never executed. |

### Validation the client enforces

* unknown top-level fields are ignored (forward compatible), but **duplicate keys,
  nesting deeper than 32, documents over 1 MiB, and strings over 8 KiB are rejected**;
* `address` must not contain schemes, whitespace, quotes, `|`, `;` or path separators;
* `path` is limited to URL-path characters (no CR/LF header injection);
* `sid` must be hex, ≤ 16 chars; `pbk` must look like an x25519 key when `security` is
  `reality`;
* raw Xray/V2Ray client configs (`inbounds`/`outbounds`) are **rejected** — running them
  would let a config file change the client's own network posture.

## 2. Locked envelope

For providers who do not want users to read or reshare the endpoint:

```
base64url( "NPVT-LOCK1" ‖ salt[16] ‖ nonce[12] ‖ tag[16] ‖ ciphertext )
```

* key = `PBKDF2-HMAC-SHA256(passphrase, salt, 210000)` → 32 bytes
* cipher = `AES-256-GCM`, plaintext = the JSON document above
* the passphrase is never stored; a wrong passphrase fails the GCM tag and produces
  `Wrong passphrase, or the file is corrupted.`

Reference implementation: `src/NpvTunnel.Core/Security/LockedConfig.cs`.

## 3. What about `.npv`, `.npv4`, `.inpv`?

Those are the closed formats used by the mobile app. Their cipher, key derivation and
binary layout are not published, so this client detects them and explains the situation
instead of guessing. Ask your provider for an `npvt/1` file or a share link.
