import json
import subprocess
from pathlib import Path


def events() -> tuple[list[tuple[str, str, str]], str]:
    binary = Path("/usr/bin/journalctl")
    if not binary.is_file():
        return [], "The systemd journal reader is unavailable."
    try:
        process = subprocess.run(
            [
                str(binary),
                "--user",
                "--no-pager",
                "-n",
                "50",
                "-o",
                "json",
                "--output-fields=__REALTIME_TIMESTAMP,_PID,PRIORITY,SYSLOG_IDENTIFIER,MESSAGE_ID",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"User journal unavailable · {exc}"
    if process.returncode:
        return [], "The current account could not read a user journal."
    records = []
    for line in process.stdout.splitlines()[-50:]:
        try:
            row = json.loads(line)
            records.append(
                (
                    str(row.get("__REALTIME_TIMESTAMP", ""))[:28],
                    str(row.get("SYSLOG_IDENTIFIER", ""))[:160],
                    f"PID {str(row.get('_PID', '—'))[:20]} · Priority "
                    f"{str(row.get('PRIORITY', '—'))[:20]}",
                )
            )
        except (ValueError, AttributeError):
            continue
    return records, "User journal metadata" if records else "No accessible user journal records."
