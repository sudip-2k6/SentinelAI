#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
tool="${APPIMAGETOOL:-appimagetool}"
if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' 'Set APPIMAGETOOL to the path of a trusted appimagetool executable.' >&2
    exit 1
fi
if [[ ! -x dist/SentinelAI/SentinelAI ]]; then
    bash scripts/build_linux.sh
fi
mkdir -p build
appdir="$(mktemp -d "$PWD/build/SentinelAI.AppDir.XXXXXXXX")"
mkdir -p "$appdir/usr/lib"
cp -a dist/SentinelAI "$appdir/usr/lib/"
cp scripts/linux/SentinelAI.desktop "$appdir/"
cp scripts/linux/sentinelai.png "$appdir/"
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
set -eu
appdir="${APPDIR:-$(dirname "$(readlink -f "$0")")}"
exec "$appdir/usr/lib/SentinelAI/SentinelAI" "$@"
EOF
chmod 0755 "$appdir/AppRun"
architecture="$(uname -m)"
ARCH="$architecture" "$tool" "$appdir" "dist/SentinelAI-$architecture.AppImage"
