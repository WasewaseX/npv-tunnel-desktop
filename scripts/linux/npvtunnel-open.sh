#!/bin/sh
# Handles a double-clicked .npvt: imports every file it is given into the
# npvtunnel store and shows what came in. Kept in a terminal on purpose - the
# import has to report refused or broken configurations to someone.
set -eu

lib=$(dirname -- "$0")
lib=$(cd -- "$lib" && pwd)
cli="$lib/npvtunnel"

if [ "$#" -eq 0 ]; then
    echo "Usage: npvtunnel-open <file.npvt> [more files...]"
    exit 2
fi

status=0
for file in "$@"; do
    printf '\n== %s ==\n' "$file"
    "$cli" import "$file" || status=1
done

printf '\n== stored configurations ==\n'
"$cli" list || status=1

printf '\nConnect with: npvtunnel connect <index>\n'
printf 'Press Enter to close this window. '
read -r _
exit $status
