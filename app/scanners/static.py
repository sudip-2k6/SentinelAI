import hashlib
import os
import stat
import struct
from pathlib import Path
from threading import Event
from typing import Protocol

from app.core.contracts import Analysis, Assessment, ScanResult
from app.core.files import open_regular
from app.features import elf, pe


class Assessor(Protocol):
    def assess(self, data: bytes, analysis: Analysis) -> Assessment: ...


def scan_file(
    path: Path, limit: int, cancel: Event, assessor: Assessor | None = None
) -> ScanResult:
    result = ScanResult(str(Path(os.path.abspath(path))), "Error")
    if cancel.is_set():
        result.status, result.message = "Cancelled", "Scan cancelled."
        return result
    try:
        contents = bytearray()
        digest = hashlib.sha256()
        with open_regular(path) as (source, info):
            result.size = info.st_size
            result.executable = (
                bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                if os.name != "nt"
                else None
            )
            if info.st_size > limit:
                result.status, result.message = "Skipped", "File exceeds the configured size limit."
                return result
            while not cancel.is_set():
                chunk = source.read(min(1024 * 1024, limit + 1 - len(contents)))
                if not chunk:
                    break
                contents.extend(chunk)
                if len(contents) > limit:
                    result.status, result.message = "Skipped", "File grew beyond the size limit."
                    return result
                digest.update(chunk)
        if cancel.is_set():
            result.status, result.message = "Cancelled", "Scan cancelled."
            return result
        result.sha256 = digest.hexdigest()
        data = bytes(contents)
        del contents
        if data.startswith(b"MZ"):
            result.format = "PE"
            result.analysis = pe.parse(data)
        elif data.startswith(b"\x7fELF"):
            result.format = "ELF"
            result.analysis = elf.parse(data)
        else:
            result.status = "Unsupported"
            result.message = (
                "Empty file." if not data else "Only PE and ELF executables are parsed."
            )
            result.assessment.reason = "No model assessment is available for this file type."
            return result
        if cancel.is_set():
            result.status, result.message = "Cancelled", "Scan cancelled."
            return result
        result.status = "Analyzed"
        if assessor is not None:
            result.assessment = assessor.assess(data, result.analysis)
    except OSError as exc:
        result.status, result.message = "Error", str(exc)
    except (ValueError, struct.error, OverflowError) as exc:
        result.status, result.message = "Malformed", str(exc)
    return result
