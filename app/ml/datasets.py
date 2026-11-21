import hashlib
import re
from array import array
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import IO
from zipfile import ZipFile

from app.ml.rich_features import archive_vector
from app.ml.schema import (
    ELF,
    ELF_HISTOGRAM,
    ELF_PRECISION,
    ELF_RICH,
    PE,
    PE_PRECISION,
    PE_RICH,
    Schema,
    numeric_vector,
)

try:
    from orjson import loads as load_json
except ImportError:
    from json import loads as load_json

_HASH = re.compile(r"[0-9a-f]{64}")
_MONTH = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])")
_MAX_LINE = 2 * 1024 * 1024
_MAX_EMBER2018_LINE = 64 * 1024 * 1024
_WEEKLY_ELF = re.compile(r"(\d{4}-\d{2}-\d{2})_(\d{4}-\d{2}-\d{2})_ELF_(train|test)\.jsonl")


@dataclass(slots=True)
class Example:
    sha256: str
    label: int
    group: str
    features: array


def _jsonl(source: IO[bytes], name: str, limit: int = _MAX_LINE) -> Iterator[tuple[int, dict]]:
    index = 0
    while line := source.readline(limit + 1):
        index += 1
        try:
            if len(line) > limit:
                raise ValueError("Dataset row exceeds the size limit.")
            if not line.strip():
                continue
            value = load_json(line)
            if not isinstance(value, dict):
                raise ValueError("Each row must be an object.")
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"{name}:{index}: {exc}") from exc
        yield index, value


def _identity(raw: dict) -> tuple[str, int]:
    sha = raw.get("sha256")
    label = raw.get("label")
    if not isinstance(sha, str) or not _HASH.fullmatch(sha) or type(label) is not int:
        raise ValueError("Invalid SHA-256 or binary label.")
    if label not in (0, 1):
        raise ValueError("Expected label 0 (benign) or 1 (malicious).")
    return sha, label


def _ember_histogram(
    raw: dict, group: str, rich_kind: str = "", *, enhanced: bool = False
) -> Example:
    sha, label = _identity(raw)
    counts = raw["histogram"]
    if (
        not isinstance(counts, list)
        or len(counts) != 256
        or any(type(count) is not int or not 0 <= count <= 1e15 for count in counts)
    ):
        raise ValueError("Expected the EMBER 256-bin integer byte histogram.")
    size = raw["general"]["size"]
    if type(size) is not int or not 0 < size <= 1e15 or size != sum(counts):
        raise ValueError("EMBER size and byte histogram totals disagree.")
    vector = array("f", [size, *(count / size for count in counts)])
    if rich_kind:
        vector.extend(archive_vector(raw, rich_kind, enhanced=enhanced))
    return Example(sha, label, group, vector)


def _ember(raw: dict, rich: bool = False, *, enhanced: bool = False) -> Example:
    month = raw.get("appeared")
    if not isinstance(month, str) or not _MONTH.fullmatch(month):
        raise ValueError("Invalid EMBER appeared month.")
    return _ember_histogram(raw, month, "PE" if rich else "", enhanced=enhanced)


def _ember2024_elf(path: Path, partition: str, adapter: str) -> Iterator[Example]:
    filename = path / f"ELF_{partition}.zip"
    with ZipFile(filename) as archive:
        members = sorted(archive.infolist(), key=lambda member: member.filename)
        if not 1 <= len(members) <= 64:
            raise ValueError(f"{filename}: expected between 1 and 64 weekly feature shards.")
        previous_end = date.min
        for member in members:
            match = _WEEKLY_ELF.fullmatch(member.filename)
            if match is None or match[3] != partition or member.file_size > 96 * 1024 * 1024:
                raise ValueError(f"{filename}: unexpected weekly feature shard.")
            start, end = date.fromisoformat(match[1]), date.fromisoformat(match[2])
            if end - start != timedelta(days=6) or start <= previous_end:
                raise ValueError(f"{filename}: invalid or overlapping shard dates.")
            previous_end = end
            name = f"{filename}/{member.filename}"
            with archive.open(member) as source:
                for row, raw in _jsonl(source, name):
                    try:
                        timestamp = raw["first_submission_date"]
                        if raw.get("file_type") != "ELF" or type(timestamp) is not int:
                            raise ValueError("Expected an ELF record with a submission timestamp.")
                        submitted = datetime.fromtimestamp(timestamp, UTC).date()
                        week = submitted - timedelta(days=(submitted.weekday() + 1) % 7)
                        yield _ember_histogram(
                            raw,
                            week.isoformat(),
                            "ELF" if adapter != "ember2024-elf" else "",
                            enhanced=adapter.endswith("-precision"),
                        )
                    except (KeyError, ValueError, TypeError, OverflowError, OSError) as exc:
                        raise ValueError(f"{name}:{row}: {exc}") from exc


def _elf(raw: dict) -> Example:
    sha, label = _identity(raw)
    group = raw.get("group")
    if raw.get("schema") != ELF.id or not isinstance(group, str) or not group or len(group) > 256:
        raise ValueError("ELF rows need the expected schema and a bounded leakage group.")
    return Example(sha, label, group, array("f", numeric_vector(raw.get("features"), ELF)))


def load(path: Path, adapter: str, *, test: bool = False) -> Iterator[Example]:
    if adapter.startswith("ember2024-elf"):
        yield from _ember2024_elf(path, "test" if test else "train", adapter)
        return
    if adapter in ("ember", "ember-rich", "ember-precision"):
        paths = (
            [path / "test_features.jsonl"] if test else sorted(path.glob("train_features_*.jsonl"))
        )
    elif adapter == "elf":
        paths = [path]
    else:
        raise ValueError(f"Unknown dataset adapter {adapter}.")
    if not paths:
        raise ValueError(f"No matching dataset files in {path}.")
    for filename in paths:
        with filename.open("rb") as source:
            # Older EMBER PE records can contain very large import or section lists.
            limit = _MAX_EMBER2018_LINE if adapter.startswith("ember") else _MAX_LINE
            for row, raw in _jsonl(source, str(filename), limit):
                if adapter.startswith("ember") and raw.get("label") == -1:
                    continue
                try:
                    yield (
                        _elf(raw)
                        if adapter == "elf"
                        else _ember(raw, adapter != "ember", enhanced=adapter == "ember-precision")
                    )
                except (KeyError, ValueError, TypeError, OverflowError) as exc:
                    raise ValueError(f"{filename}:{row}: {exc}") from exc


def unique_partitions(*partitions: list[Example]) -> tuple[list[Example], ...]:
    """Keep first observations and drop SHA or float32-vector duplicates across splits."""
    labels: dict[str, int] = {}
    vectors: dict[bytes, int] = {}
    output: list[list[Example]] = []
    for partition in partitions:
        kept = []
        for item in partition:
            fingerprint = hashlib.blake2b(item.features.tobytes(), digest_size=16).digest()
            by_hash, by_vector = labels.get(item.sha256), vectors.get(fingerprint)
            if by_hash is not None and by_hash != item.label:
                raise ValueError(f"Conflicting labels for {item.sha256}.")
            labels[item.sha256] = item.label
            # A projected feature collision cannot leak the same vector into multiple splits.
            if by_vector is not None or by_hash is not None:
                continue
            vectors[fingerprint] = item.label
            kept.append(item)
        output.append(kept)
    return tuple(output)


def schema_for(adapter: str) -> Schema:
    if adapter == "ember":
        return PE
    if adapter == "elf":
        return ELF
    if adapter == "ember2024-elf":
        return ELF_HISTOGRAM
    if adapter == "ember-rich":
        return PE_RICH
    if adapter == "ember2024-elf-rich":
        return ELF_RICH
    if adapter == "ember-precision":
        return PE_PRECISION
    if adapter == "ember2024-elf-precision":
        return ELF_PRECISION
    raise ValueError(f"Unknown adapter {adapter}.")
