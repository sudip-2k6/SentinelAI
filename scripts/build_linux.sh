#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
sentinel_python="${PYTHON:-python3}"
mkdir -p build
"$sentinel_python" -m PyInstaller --noconfirm --windowed --onedir --name SentinelAI \
    --specpath build --workpath build/pyinstaller --distpath dist \
    --collect-binaries lightgbm --collect-data lightgbm --exclude-module pandas --exclude-module matplotlib \
    --exclude-module IPython --exclude-module pytest --exclude-module tkinter app/__main__.py
if [[ "${1:-}" == "--smoke-test" ]]; then
    smoke_dir="$(mktemp -d)"
    dist/SentinelAI/SentinelAI --smoke-test --data-dir "$smoke_dir"
fi
