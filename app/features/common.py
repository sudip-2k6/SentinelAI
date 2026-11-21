import math
import re
from collections import Counter

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore[assignment]

# Patterns are fixed byte literals. Only aggregate counts are retained.
_PATTERNS = {
    "Network URL markers": re.compile(rb"https?://", re.IGNORECASE),
    "PowerShell string markers": re.compile(rb"powershell(?:\.exe)?", re.IGNORECASE),
    "Command shell markers": re.compile(rb"cmd\.exe|/bin/(?:ba)?sh", re.IGNORECASE),
    "Registry hive markers": re.compile(rb"HKEY_[A-Z_]+"),
    "Windows path markers": re.compile(rb"[A-Za-z]:\\"),
}


def normalized_histogram(data: bytes) -> list[float]:
    if not data:
        return [0.0] * 256
    if np is not None:
        counts_array = np.zeros(256, dtype=np.int64)
        payload = np.frombuffer(data, dtype=np.uint8)
        for offset in range(0, len(data), 512 * 1024):
            counts_array += np.bincount(payload[offset : offset + 512 * 1024], minlength=256)
        return (counts_array / len(data)).tolist()
    counts: Counter[int] = Counter()
    view = memoryview(data)
    # Counter holds the GIL while consuming a chunk. Bound that interval so Qt can
    # process Python callbacks even when several workers are analyzing large files.
    for offset in range(0, len(data), 128 * 1024):
        counts.update(view[offset : offset + 128 * 1024])
    return [counts[index] / len(data) for index in range(256)]


def entropy(data: bytes) -> float:
    return -sum(p * math.log2(p) for p in normalized_histogram(data) if p)


def indicators(data: bytes) -> dict[str, int]:
    # Limit repetitive scans of large inputs. A missing marker beyond this window is unknown.
    window = data[: 4 * 1024 * 1024]
    return {name: sum(1 for _ in pattern.finditer(window)) for name, pattern in _PATTERNS.items()}


def printable(raw: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "?" for byte in raw)
