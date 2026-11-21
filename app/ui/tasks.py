import logging
from collections.abc import Callable
from threading import Event
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot

log = logging.getLogger(__name__)


class TaskSignals(QObject):
    progress = Signal(object)
    done = Signal(object)
    failed = Signal(str)
    finished = Signal()


class Task(QRunnable):
    def __init__(self, run: Callable[[Event, Callable[[Any], None]], Any]) -> None:
        super().__init__()
        self.function = run
        self.cancel = Event()
        self.signals = TaskSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.done.emit(self.function(self.cancel, self.signals.progress.emit))
        except Exception as exc:
            log.exception("Worker failed", extra={"operation": "background_task"})
            self.signals.failed.emit(str(exc))
        finally:
            self.signals.finished.emit()
