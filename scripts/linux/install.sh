#!/bin/sh
# Installs npvtunnel for the current user (no root, nothing outside $HOME).
#   sh install.sh                install under ~/.local
#   PREFIX=/opt/x sh install.sh  install somewhere else
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix=${PREFIX:-"$HOME/.local"}
lib="$prefix/lib/npvtunnel"
bin="$prefix/bin"

if [ "$(id -u)" -eq 0 ] && [ -z "${PREFIX:-}" ]; then
    echo "Refusing to install into /root by default. Set PREFIX or run as your own user." >&2
    exit 1
fi

echo "Installing npvtunnel into $lib"
mkdir -p "$lib" "$bin" "$prefix/share/applications" "$prefix/share/mime/packages"
cp -f "$here/npvtunnel" "$lib/npvtunnel"
cp -f "$here/npvtunnel-open.sh" "$lib/npvtunnel-open.sh"
rm -rf "$lib/core"
cp -R "$here/core" "$lib/core"
cp -f "$here/LICENSE" "$here/THIRD-PARTY-NOTICES.md" "$lib/" 2>/dev/null || true
cp -f "$here/README-linux.md" "$lib/README.md" 2>/dev/null || true
chmod 0755 "$lib/npvtunnel" "$lib/npvtunnel-open.sh"
chmod 0755 "$lib/core/xray" 2>/dev/null || true
chmod 0644 "$lib/core/ENGINE.sha256"

ln -sf "$lib/npvtunnel" "$bin/npvtunnel"
ln -sf "$lib/npvtunnel-open.sh" "$bin/npvtunnel-open"

# Detect the .npvt extension so a double-click lands in the importer, the way the
# Windows setup registers the same association.
cat > "$prefix/share/mime/packages/npvtunnel.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-npvt">
    <comment>NPV Tunnel configuration</comment>
    <glob pattern="*.npvt" weight="60"/>
    <glob pattern="*.npv" weight="40"/>
    <glob pattern="*.npv4" weight="40"/>
  </mime-type>
</mime-info>
XML

cat > "$prefix/share/applications/npvtunnel-open.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Import NPV configuration
Comment=Import a .npvt configuration into npvtunnel
Exec=$lib/npvtunnel-open.sh %f
Terminal=true
NoDisplay=true
MimeType=application/x-npvt;
Categories=Network;
DESKTOP

if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database "$prefix/share/mime" 2>/dev/null || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
    xdg-mime default npvtunnel-open.desktop application/x-npvt 2>/dev/null || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$prefix/share/applications" 2>/dev/null || true
fi

case ":$PATH:" in
    *":$bin:"*) ;;
    *) echo "Add $bin to PATH, for example: echo 'export PATH=\"$bin:\$PATH\"' >> ~/.profile" ;;
esac

echo
echo "Installed. Try:"
echo "  npvtunnel selftest          # proves the binary and the engine work here"
echo "  npvtunnel import file.npvt  # or just double-click the file"
echo "  npvtunnel connect 0         # run the tunnel on the foreground"
