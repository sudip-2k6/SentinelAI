import hashlib
from pathlib import Path
from threading import Event

import pytest

from app.core.settings import Settings
from app.database.history import History
from app.scanners.jobs import candidates, run_scan
from app.scanners.static import scan_file
from tests.fixtures import elf_fixture, pe_fixture


@pytest.mark.parametrize(
    ("data", "status", "kind"),
    [
        (pe_fixture(), "Analyzed", "PE"),
        (elf_fixture(), "Analyzed", "ELF"),
        (b"MZ", "Malformed", "PE"),
        (b"\x7fELF", "Malformed", "ELF"),
        (b"hello", "Unsupported", "Unknown"),
        (b"", "Unsupported", "Unknown"),
    ],
)
def test_file_formats(tmp_path: Path, data: bytes, status: str, kind: str) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(data)
    result = scan_file(target, 4096, Event())
    assert (result.status, result.format, result.sha256) == (
        status,
        kind,
        hashlib.sha256(data).hexdigest(),
    )
    assert result.assessment.probability is None
    assert result.assessment.status == "Unavailable"
    if kind == "PE" and result.analysis:
        assert result.analysis.sections[0]["executable"] == 1


def test_limit_error_directory_and_cancellation(tmp_path: Path) -> None:
    destination = tmp_path / "huge.sparse"
    with destination.open("wb") as handle:
        handle.truncate(2**30)
    cancel = Event()
    assert scan_file(destination, 8, cancel).status == "Skipped"
    assert scan_file(tmp_path, 8, cancel).status == "Error"
    assert scan_file(tmp_path / "missing", 8, cancel).status == "Error"
    cancel.set()
    assert scan_file(destination, 8, cancel).status == "Cancelled"


def test_history_and_recursive_scan(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir()
    history = History(private)
    sample = tmp_path / "data" / "sample%.elf"
    sample.parent.mkdir()
    sample.write_bytes(elf_fixture())
    (sample.parent / "other.exe").write_bytes(pe_fixture())
    settings = Settings()
    event = Event()
    result = run_scan(
        candidates(tmp_path, True, settings, private, event),
        settings,
        private,
        event,
        lambda item: history.record(item, "test"),
        parallel=True,
    )
    assert result.total == result.analyzed == 2
    values = history.recent("%", "Analyzed", hashlib.sha256(elf_fixture()).hexdigest())
    assert len(values) == 1
    assert history.detail(values[0]["id"])["analysis"]["headers"]["Architecture"] == 64
    history.engine.dispose()


def test_symbolic_links_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.elf"
    real.write_bytes(elf_fixture())
    link = tmp_path / "link"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("Symbolic link creation is not permitted on this host")
    assert scan_file(link, 4096, Event()).status == "Error"
