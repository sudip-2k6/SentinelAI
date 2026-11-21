import os
import sys
from dataclasses import dataclass
from pathlib import Path
from threading import Event

import psutil

from app.core.contracts import ScanResult


@dataclass(frozen=True, slots=True)
class ProcessRow:
    pid: int
    parent: int
    name: str
    cpu: float
    memory: int
    started: float


class ProcessSampler:
    def __init__(self) -> None:
        self.previous: dict[int, tuple[float, psutil.Process]] = {}

    def sample(self, cancel: Event) -> tuple[list[ProcessRow], int]:
        rows, unavailable = [], 0
        next_sample: dict[int, tuple[float, psutil.Process]] = {}
        for pid in psutil.pids()[:2048]:
            if cancel.is_set():
                break
            try:
                observed = psutil.Process(pid)
                started = observed.create_time()
                previous = self.previous.get(pid)
                proc = previous[1] if previous and previous[0] == started else observed
                with proc.oneshot():
                    rows.append(
                        ProcessRow(
                            pid,
                            proc.ppid(),
                            proc.name(),
                            proc.cpu_percent(),
                            proc.memory_info().rss,
                            started,
                        )
                    )
                next_sample[pid] = (started, proc)
            except (psutil.Error, OSError):
                unavailable += 1
        self.previous = next_sample
        return rows, unavailable


def inspect(pid: int, started: float) -> Path | ScanResult:
    try:
        proc = psutil.Process(pid)
        if proc.create_time() != started:
            raise ValueError("This process ID has been reused. Refresh the process list.")
        executable = proc.exe()
        if not executable or proc.create_time() != psutil.Process(pid).create_time():
            raise ValueError("The executable is unavailable or the process changed.")
        return Path(executable)
    except (psutil.Error, OSError, ValueError) as exc:
        return ScanResult(f"Process {pid}", "Error", message=str(exc))


def system_events() -> tuple[list[tuple[str, str, str]], str]:
    if os.name == "nt":
        from app.platforms.windows.telemetry import events
    elif sys.platform.startswith("linux"):
        from app.platforms.linux.telemetry import events
    else:
        return [], "System event metadata is unavailable on this platform."
    try:
        return events()
    except (OSError, ImportError, RuntimeError) as exc:
        return [], f"System event metadata unavailable · {exc}"
