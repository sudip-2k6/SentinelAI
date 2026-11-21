import fnmatch
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import batched, islice
from pathlib import Path
from threading import Event
from time import monotonic

from app.core.contracts import ScanResult
from app.core.files import beneath, check_chain, is_link, local_path
from app.core.settings import Settings
from app.scanners.static import Assessor, scan_file

_MAX_FILES = 100_000


def excluded(path: Path, patterns: list[str], private_root: Path) -> bool:
    if beneath(path, private_root):
        return True
    absolute = path.as_posix()
    return any(
        fnmatch.fnmatch(absolute, pattern)
        or any(fnmatch.fnmatch(part, pattern) for part in path.parts)
        for pattern in patterns
    )


def candidates(
    root: Path,
    recursive: bool,
    settings: Settings,
    private_root: Path,
    cancel: Event,
) -> Iterator[Path | ScanResult]:
    try:
        root = local_path(root)
        check_chain(root)
        if not root.is_dir():
            raise NotADirectoryError(str(root))
    except OSError as exc:
        yield ScanResult(str(root), "Error", message=str(exc))
        return
    if excluded(root, settings.exclusions, private_root):
        yield ScanResult(str(root), "Skipped", message="Directory excluded by settings.")
        return

    def walk(directory: Path, depth: int) -> Iterator[Path | ScanResult]:
        if depth >= 64:
            yield ScanResult(str(directory), "Skipped", message="Directory nesting limit reached.")
            return
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if cancel.is_set():
                        return
                    path = Path(entry.path)
                    if excluded(path, settings.exclusions, private_root):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if is_link(info):
                            continue
                        if stat.S_ISDIR(info.st_mode) and recursive:
                            yield from walk(path, depth + 1)
                        elif stat.S_ISREG(info.st_mode):
                            yield path
                    except OSError as exc:
                        yield ScanResult(str(path), "Error", message=str(exc))
        except OSError as exc:
            yield ScanResult(str(directory), "Error", message=str(exc))

    yield from walk(root, 0)


@dataclass(slots=True)
class ScanSummary:
    total: int = 0
    analyzed: int = 0
    issues: int = 0
    flagged: int = 0
    cancelled: bool = False
    capped: bool = False


def run_scan(
    paths: Iterable[Path | ScanResult],
    settings: Settings,
    private_root: Path,
    cancel: Event,
    record: Callable[[ScanResult], None],
    assessor: Assessor | None = None,
    *,
    parallel: bool = False,
) -> ScanSummary:
    summary = ScanSummary()
    throttle = 100 / settings.scan_duty_percent - 1

    def process(target: Path | ScanResult) -> ScanResult:
        started = monotonic()
        if isinstance(target, ScanResult):
            result = target
        elif excluded(Path(os.path.abspath(target)), settings.exclusions, private_root):
            result = ScanResult(str(target), "Skipped", message="File excluded by settings.")
        else:
            result = scan_file(target, settings.max_mib * 1024 * 1024, cancel, assessor)
        if throttle:
            cancel.wait(min(2.0, (monotonic() - started) * throttle))
        return result

    def consume(results: Iterable[ScanResult]) -> None:
        for result in results:
            if result.status == "Cancelled":
                return
            record(result)
            summary.total += 1
            summary.analyzed += result.status == "Analyzed"
            summary.issues += result.status in ("Error", "Malformed", "Skipped")
            summary.flagged += result.assessment.review == "Elevated model score"

    targets = iter(paths)
    workers = settings.scan_workers if parallel else 1
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sentinel-scan") as executor:
        for batch in batched(islice(targets, _MAX_FILES), workers):
            if cancel.is_set():
                break
            consume(executor.map(process, batch) if workers > 1 else map(process, batch))
    summary.cancelled = cancel.is_set()
    if not summary.cancelled and summary.total == _MAX_FILES:
        summary.capped = next(targets, None) is not None
    return summary
