import argparse
import json
import logging
import os
import stat
import sys
from pathlib import Path

from PySide6.QtCore import QLockFile, Qt, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox
from sqlalchemy.exc import SQLAlchemyError

from app.core.contracts import ScanResult
from app.core.files import check_chain, local_path
from app.core.settings import Settings, default_root
from app.database.history import History
from app.platforms.linux.access import current_uid
from app.scanners.static import scan_file
from app.ui.theme import apply_theme
from app.ui.window import Window


class JsonLog(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname,
                "logger": record.name,
                "operation": getattr(record, "operation", None),
                "message": record.getMessage(),
                "exception": self.formatException(record.exc_info) if record.exc_info else None,
            }
        )


def prepare_root(root: Path) -> Path:
    root = local_path(root)
    missing = root
    while not missing.exists():
        missing = missing.parent
    check_chain(missing)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_chain(root)
    if os.name != "nt":
        info = root.stat()
        if info.st_uid != current_uid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise OSError("The application data directory must be owned by you and mode 0700.")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelai")
    parser.add_argument("--data-dir", type=Path, default=default_root(), help=argparse.SUPPRESS)
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)

    if options.smoke_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    if sys.stderr is not None:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLog())
        logging.basicConfig(handlers=[handler], level=logging.WARNING)
    application = QApplication(["SentinelAI"])
    application.setApplicationName("SentinelAI")
    application.setStyle("Fusion")
    try:
        root = prepare_root(options.data_dir)
        lock = QLockFile(str(root / "instance.lock"))
        lock.setStaleLockTime(0)
        if not lock.tryLock(0):
            raise OSError("Another SentinelAI instance owns this application data directory.")
        settings = Settings.load(root)
        history = History(root)
        history.prune(settings.retention_days)
        apply_theme(application, settings.theme)
        window = Window(root, settings, history)
    except (OSError, ValueError, SQLAlchemyError) as exc:
        if not options.smoke_test:
            message = QMessageBox()
            message.setWindowTitle("SentinelAI could not start")
            message.setTextFormat(Qt.TextFormat.PlainText)
            message.setText(str(exc))
            message.exec()
        else:
            logging.error("Startup failed: %s", exc)
        return 1
    window.show()
    smoke_status = 0
    if options.smoke_test:

        def smoke_done(result: ScanResult) -> None:
            nonlocal smoke_status
            if result.status != "Analyzed" or result.assessment.probability is not None:
                logging.error("Static smoke scan failed: %s %s", result.status, result.message)
                smoke_status = 1
            else:
                history.record(result, "Static smoke")
                if not result.sha256 or not history.recent(sha256=result.sha256):
                    smoke_status = 1
            QTimer.singleShot(0, window.close)

        def smoke_failed(message: str) -> None:
            nonlocal smoke_status
            logging.error("Static smoke worker failed: %s", message)
            smoke_status = 1
            QTimer.singleShot(0, window.close)

        window.launch(
            lambda cancel, _: scan_file(Path(sys.executable), 32 * 1024 * 1024, cancel),
            smoke_done,
            fail=smoke_failed,
        )
    try:
        exit_status = application.exec()
        if options.smoke_test and getattr(sys, "frozen", False):
            outcome = root / "smoke-result.txt"
            try:
                import lightgbm

                if not lightgbm.__version__ or window.quarantine_service is None:
                    raise RuntimeError(
                        "Packaged inference or quarantine support did not initialize."
                    )
            except Exception as exc:
                outcome.write_text(f"{type(exc).__name__}: {exc}", encoding="utf-8")
                return 1
            outcome.write_text("Packaged runtime initialized.", encoding="utf-8")
        return exit_status or smoke_status
    finally:
        lock.unlock()
        history.engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
