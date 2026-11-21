import os
from pathlib import Path
from threading import Event
from time import monotonic

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from app.core.contracts import ScanResult
from app.core.settings import Settings
from app.database.history import History
from app.ui.details import report_markup, write_report
from app.ui.theme import apply_theme
from app.ui.window import Window
from tests.fixtures import pe_fixture


@pytest.fixture(scope="module")
def qt() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication([])


def test_native_scan_to_history_and_export(qt: QApplication, tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    executable = tmp_path / "trusted & inert.exe"
    executable.write_bytes(pe_fixture())
    apply_theme(qt, "Dark")
    history = History(root)
    window = Window(root, Settings(), history)
    window.show()
    try:
        window.go("Quick Scan")
        window.start_scan(window.quick, [executable], "UI smoke", one=True)
        deadline = monotonic() + 6
        while (window.scan_task is not None or window.tasks) and monotonic() < deadline:
            QTest.qWait(30)
        assert window.scan_task is None and window.quick.results_model.rowCount() == 1
        assert window.quick.records[0].format == "PE"
        assert window.quick.records[0].assessment.probability is None
        assert window.quick.progress.value() == 1
        window.go("Threat History")
        window.hash_query.setText(window.quick.records[0].sha256 or "")
        deadline = monotonic() + 6
        while (window.search_delay.isActive() or window.history_task) and monotonic() < deadline:
            QTest.qWait(20)
        (item,) = window.history_model.records
        data = history.detail(item["id"])
        data["path"] += ' <img src="https://example.invalid/pixel">'
        markup = report_markup(data)
        assert "&lt;img src=" in markup and "<img src=" not in markup
        destination = tmp_path / "report.pdf"
        write_report(destination, markup, "PDF")
        assert destination.read_bytes().startswith(b"%PDF-")
        destination = tmp_path / "report.html"
        write_report(destination, markup, "HTML")
        assert data["sha256"] in destination.read_text(encoding="utf-8")
    finally:
        window.close()
        QTest.qWait(20)
        history.engine.dispose()


def test_folder_updates_keep_selection_and_cancellation_responsive(
    qt: QApplication,
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    history = History(root)
    window = Window(root, Settings(), history)
    window.show()
    try:
        window.go("Folder Scan")
        page = window.folder
        page.update([ScanResult("selected.exe", "Analyzed")])
        page.results.selectRow(0)
        page.update([ScanResult("later.exe", "Analyzed")])
        assert page.results.currentIndex().row() == 1
        assert page.records[1].path == "selected.exe"
        page.update([ScanResult(f"{i}.exe", "Analyzed") for i in range(300)])
        assert page.results_model.rowCount() == 250
        assert page.records[0].path == "299.exe"

        def targets(cancel):
            while not cancel.wait(0.01):
                yield ScanResult("folder entry", "Unsupported")

        window.start_scan(page, targets, "Folder regression", one=False)
        QTimer.singleShot(600, page.cancel.click)
        deadline = monotonic() + 5
        while window.scan_task is not None and monotonic() < deadline:
            QTest.qWait(20)
        assert window.scan_task is None
        assert page.status.text().startswith("Cancelled")
        assert page.results_model.rowCount() > 0
    finally:
        window.close()
        QTest.qWait(20)
        history.engine.dispose()


def test_history_remains_responsive_and_discards_stale_results(
    qt: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    history = History(root)
    history.record(ScanResult("old.exe", "Analyzed"), "test")
    history.record(ScanResult("new.exe", "Analyzed"), "test")
    window = Window(root, Settings(scan_workers=1), history)
    window.show()
    release_scan = Event()
    release_query = Event()
    scan_started = Event()
    query_started = Event()
    recent = history.recent
    displayed_paths: list[str] = []
    window.history_model.modelReset.connect(
        lambda: displayed_paths.extend(item["path"] for item in window.history_model.records)
    )

    def delayed_recent(query="", status="", sha256="", *, limit=250, cancel=None):
        if not query:
            query_started.set()
            release_query.wait(5)
        return recent(query, status, sha256, limit=limit)

    def wait_for(predicate):
        deadline = monotonic() + 5
        while not predicate() and monotonic() < deadline:
            QTest.qWait(20)
        assert predicate()

    try:
        wait_for(lambda: not window.tasks)

        def occupy_scan_worker(_cancel, _emit):
            scan_started.set()
            release_scan.wait(10)

        window.launch(occupy_scan_worker, lambda _: None)
        wait_for(scan_started.is_set)
        monkeypatch.setattr(history, "recent", delayed_recent)
        window.nav_buttons["Threat History"].click()
        wait_for(query_started.is_set)
        assert window.history_visible()
        assert window.history_status.text() == "Loading history…"
        window.nav_buttons["Quarantine"].click()
        assert window.stack.currentWidget() is window.pages["Quarantine"]
        window.nav_buttons["Threat History"].click()
        window.query.setText("new")
        QTimer.singleShot(30, release_query.set)
        wait_for(lambda: window.history_status.text() == "Showing 1 latest results")
        assert [item["path"] for item in window.history_model.records] == ["new.exe"]
        assert displayed_paths == ["new.exe"]
        assert not release_scan.is_set()
    finally:
        release_scan.set()
        release_query.set()
        wait_for(lambda: not window.tasks)
        window.close()
        history.engine.dispose()


def test_optional_lief_header_cross_check(tmp_path: Path) -> None:
    pytest.importorskip("lief")
    from scripts.audit_pe import audit

    executable = tmp_path / "header-only.exe"
    executable.write_bytes(pe_fixture())
    result = audit(executable)
    assert result["sections"] == 1 and result["entry_point_rva"] == 4096
