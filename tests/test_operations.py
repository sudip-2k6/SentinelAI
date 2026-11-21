import hashlib
import os
from pathlib import Path
from threading import Event
from time import monotonic, sleep

import pytest

from app.core.settings import Settings
from app.database.history import History
from app.monitoring.files import FileMonitor
from app.monitoring.processes import ProcessSampler, inspect
from app.quarantine.service import Quarantine
from tests.fixtures import elf_fixture


def test_confirmed_quarantine_duplicate_restore_and_protected_paths(tmp_path: Path) -> None:
    data = tmp_path / "app"
    data.mkdir(mode=0o700)
    history = History(data)
    service = Quarantine(data, history, home=tmp_path)
    sample = tmp_path / "sample.elf"
    payload = elf_fixture()
    sample.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError, match="explicit approval"):
        service.store(sample, digest)
    with pytest.raises(OSError, match="changed"):
        service.store(sample, "a" * 64, confirmed=True)
    with pytest.raises(ValueError, match="protected"):
        service.store(tmp_path / ".ssh" / "file", digest, confirmed=True)
    entry = service.store(sample, digest, confirmed=True)
    assert not sample.exists() and service.items()[0]["state"] == "Isolated"
    sample.write_bytes(b"replacement")
    with pytest.raises(FileExistsError):
        service.restore(entry, confirmed=True)
    with pytest.raises(ValueError, match="original directory"):
        service.restore(entry, tmp_path / "elsewhere" / "copy.elf", confirmed=True)
    restored = service.restore(entry, tmp_path / "copy.elf", confirmed=True)
    assert restored.read_bytes() == payload and sample.read_bytes() == b"replacement"
    assert service.items()[0]["state"] == "Restored"
    history.engine.dispose()


def test_quarantine_recovery_and_integrity(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir(mode=0o700)
    history = History(root)
    service = Quarantine(root, history, home=tmp_path)
    source = tmp_path / "example"
    source.write_bytes(b"inert")
    digest = hashlib.sha256(b"inert").hexdigest()
    entry = service.store(source, digest, confirmed=True)
    service._state(entry, "Staging")
    service.recover()
    assert service.items()[0]["state"] == "Isolated"
    service._payload(entry).write_bytes(b"changed")
    with pytest.raises(OSError, match="integrity"):
        service.restore(entry, confirmed=True)
    assert service.items()[0]["state"] == "Recovery required"
    assert not source.exists()
    history.engine.dispose()


def test_watch_debounce_and_exclusions(tmp_path: Path) -> None:
    data, watch = tmp_path / "private", tmp_path / "watched"
    data.mkdir()
    watch.mkdir()
    settings = Settings(watch_dirs=[str(watch)], debounce_ms=250, exclusions=["*.ignore"])
    monitor = FileMonitor(settings, data)
    try:
        sample = watch / "sample.elf"
        sample.write_bytes(elf_fixture())
        (watch / "skipped.ignore").write_bytes(b"ignore")
        results = []
        deadline = monotonic() + 5
        while monotonic() < deadline and not results:
            results = monitor.drain()
            sleep(0.08)
        assert results == [sample]
    finally:
        monitor.stop()


def test_local_process_inspection() -> None:
    rows, _ = ProcessSampler().sample(Event())
    own = next(row for row in rows if row.pid == os.getpid())
    result = inspect(own.pid, own.started)
    assert isinstance(result, Path) and result.is_file()
    err = inspect(own.pid, own.started - 60)
    assert not isinstance(err, Path) and "reused" in err.message
