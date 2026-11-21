#!/bin/bash
set -euo pipefail
umask 077

state=/tmp/sentinel-desktop
mkdir -p "$state"
export XDG_RUNTIME_DIR="$state"

python - <<'PY' > "$state/password"
from secrets import choice
from string import ascii_letters, digits

print("".join(choice(ascii_letters + digits) for _ in range(8)))
PY
tigervncpasswd -f < "$state/password" > "$state/vnc-passwd"

pids=()
stop_desktop() {
    if (( ${#pids[@]} )); then
        kill "${pids[@]}" 2>/dev/null || true
        wait || true
    fi
}
trap stop_desktop EXIT
trap 'exit 0' INT TERM

Xtigervnc "$DISPLAY" -geometry 1440x900 -depth 24 -localhost yes -nolisten tcp \
    -SecurityTypes VncAuth -PasswordFile "$state/vnc-passwd" &
pids+=("$!")

for attempt in {1..50}; do
    if xdpyinfo >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
xdpyinfo >/dev/null

openbox &
pids+=("$!")
python -m app &
pids+=("$!")
websockify --web /usr/share/novnc 0.0.0.0:6080 127.0.0.1:5900 &
pids+=("$!")
wait -n "${pids[@]}"
