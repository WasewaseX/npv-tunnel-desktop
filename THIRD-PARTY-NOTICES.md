# Third-party notices

## Xray-core

* Version: **v26.11.9** (pinned)
* License: **MPL-2.0**
* Upstream: <https://github.com/XTLS/Xray-core>
* Distribution: bundled as `core\xray.exe` in the release archives, and optionally fetched
  at runtime by Settings → *Install core*.
* Integrity: archive SHA-256 `1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`
  and binary SHA-256 `1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185`,
  both compiled into the application (`EngineManifest.cs`).
* The full upstream license text ships next to the binary as `core\LICENSE-xray.txt`.
  Modified MPL-2.0 files: none — the binary is redistributed unmodified.

## geoip.dat / geosite.dat

Data files published in the Xray-core release archive, used for the `geoip:private`
routing rule. Same license and provenance as above.

## .NET / WPF

* Microsoft .NET 8 and Windows Desktop runtime, MIT licensed.
* `System.Security.Cryptography.ProtectedData` — MIT, Microsoft.

## Icons

The application icon and the UI glyphs are drawn with GDI+/Segoe MDL2 Assets, or generated
for this project. No third-party icon set is redistributed.

## Not used, on purpose

No Electron, no CEF/WebView2, no bundled browser. No analytics, crash-reporting or
telemetry SDKs of any kind.
