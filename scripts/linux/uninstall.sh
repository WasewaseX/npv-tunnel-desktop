#!/bin/sh
# Removes the files install.sh created. Profiles in ~/.config/npvtunnel are kept
# unless you pass --purge.
set -eu

purge=0
for arg in "$@"; do
    case $arg in
        --purge) purge=1 ;;
        *) echo "Unknown option $arg" >&2; exit 2 ;;
    esac
done

prefix=${PREFIX:-"$HOME/.local"}
lib="$prefix/lib/npvtunnel"
bin="$prefix/bin"

rm -f "$bin/npvtunnel" "$bin/npvtunnel-open"
rm -f "$prefix/share/applications/npvtunnel-open.desktop"
rm -f "$prefix/share/mime/packages/npvtunnel.xml"
rm -rf "$lib"

if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database "$prefix/share/mime" 2>/dev/null || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$prefix/share/applications" 2>/dev/null || true
fi

if [ "$purge" -eq 1 ]; then
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/npvtunnel"
    echo "Removed the store as well."
else
    echo "Left ${XDG_CONFIG_HOME:-$HOME/.config}/npvtunnel in place (use --purge to delete it)."
fi

echo "npvtunnel uninstalled."
