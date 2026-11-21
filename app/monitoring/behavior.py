import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.core.files import open_regular

MAX_REPORT = 8 * 1024 * 1024
MAX_EVENTS = 25_000
SCHEMA = "sentinel-behavior-v1"
CATEGORIES = (
    "process",
    "thread",
    "file",
    "registry",
    "network",
    "memory",
    "service",
    "synchronization",
    "other",
)
_CAPE_CATEGORIES = {
    "filesystem": "file",
    "file": "file",
    "files": "file",
    "registry": "registry",
    "process": "process",
    "thread": "thread",
    "services": "service",
    "service": "service",
    "network": "network",
    "socket": "network",
    "memory": "memory",
    "synchronisation": "synchronization",
    "synchronization": "synchronization",
}


@dataclass(frozen=True, slots=True)
class BehaviorSummary:
    source: str
    counts: dict[str, int]
    sequences: tuple[tuple[str, ...], ...]
    processes: int
    truncated: bool

    @property
    def events(self) -> int:
        return sum(self.counts.values())


def _normalized(raw: dict) -> BehaviorSummary:
    events = raw.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("Normalized reports need an events array with at most 25,000 entries.")
    sequences: dict[int, list[str]] = {}
    last = 0.0
    for item in events:
        if not isinstance(item, dict):
            raise ValueError("Invalid behavioral event.")
        kind, stamp, pid = item.get("category"), item.get("time_ms"), item.get("pid")
        if (
            not isinstance(kind, str)
            or kind not in CATEGORIES
            or not isinstance(stamp, (int, float))
            or isinstance(stamp, bool)
            or not 0 <= stamp <= 30 * 24 * 60 * 60 * 1000
            or not math.isfinite(stamp)
            or stamp < last
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not 0 <= pid <= 2**32 - 1
        ):
            raise ValueError(
                "Events must have ordered time_ms, a numeric PID, and a known category."
            )
        last = stamp
        sequences.setdefault(pid, []).append(kind)
    return _summary("SentinelAI normalized JSON", list(sequences.values()), False)


def _cape(raw: dict) -> BehaviorSummary:
    behavior = raw.get("behavior")
    processes = behavior.get("processes") if isinstance(behavior, dict) else None
    if not isinstance(processes, list):
        raise ValueError("Unsupported behavioral report schema.")
    sequences: list[list[str]] = []
    count = 0
    for proc in processes[:2048]:
        if not isinstance(proc, dict) or not isinstance(proc.get("calls"), list):
            raise ValueError("A sandbox process entry has no inline calls array.")
        sequence = []
        limit = MAX_EVENTS - count
        for event in proc["calls"][:limit]:
            if not isinstance(event, dict):
                raise ValueError("Invalid sandbox API call entry.")
            item = event.get("category")
            key = item.lower() if isinstance(item, str) and len(item) <= 64 else ""
            sequence.append(_CAPE_CATEGORIES.get(key, "other"))
        sequences.append(sequence)
        count += len(sequence)
        if count >= MAX_EVENTS:
            break
    return _summary(
        "CAPE/Cuckoo-style inline JSON",
        sequences,
        count >= MAX_EVENTS or len(processes) > len(sequences),
    )


def _summary(source: str, sequences: list[list[str]], truncated: bool) -> BehaviorSummary:
    counts = Counter(category for sequence in sequences for category in sequence)
    return BehaviorSummary(
        source,
        {name: counts[name] for name in CATEGORIES},
        tuple(tuple(sequence) for sequence in sequences),
        len(sequences),
        truncated,
    )


def import_report(path: Path) -> BehaviorSummary:
    with open_regular(path) as (stream, info):
        if info.st_size > MAX_REPORT:
            raise ValueError("Behavioral report exceeds 8 MiB. Export the normalized summary.")
        data = stream.read(MAX_REPORT + 1)
    if len(data) > MAX_REPORT:
        raise ValueError("Behavioral report exceeds 8 MiB.")
    try:
        report = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Behavioral report must be a valid, bounded JSON object.") from exc
    if not isinstance(report, dict):
        raise ValueError("Behavioral report must be a JSON object.")
    if report.get("schema") == SCHEMA:
        return _normalized(report)
    if "schema" in report:
        raise ValueError("Unsupported behavioral report schema version.")
    return _cape(report)
