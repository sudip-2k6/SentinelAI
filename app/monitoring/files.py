import logging
import os
from collections import OrderedDict
from pathlib import Path
from queue import Full
from threading import Lock
from time import monotonic

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import EventQueue

from app.core.files import check_chain, local_path
from app.core.settings import Settings
from app.scanners.jobs import excluded

log = logging.getLogger(__name__)


class EventBuffer(EventQueue):
    def __init__(self) -> None:
        super().__init__(maxsize=2048)
        self.dropped = 0

    def put(self, item, block=True, timeout=None) -> None:
        if not isinstance(item, tuple):  # allow the observer stop sentinel to drain
            super().put(item, block, timeout)
            return
        try:
            super().put(item, block=False)
        except Full:
            self.dropped += 1


class FileMonitor(FileSystemEventHandler):
    def __init__(self, settings: Settings, root: Path) -> None:
        self.root, self.settings = root, settings
        self.pending: OrderedDict[Path, float] = OrderedDict()
        self.lock = Lock()
        self.dropped = 0
        self.observer = Observer(timeout=0.5)
        self.queue = EventBuffer()
        self.observer._event_queue = self.queue
        paths = list(dict.fromkeys(local_path(Path(name)) for name in settings.watch_dirs))
        if not 1 <= len(paths) <= 8:
            raise ValueError("Configure one to eight watch directories before starting.")
        if any(directory in other.parents for directory in paths for other in paths):
            raise ValueError("Use non-overlapping watch directories.")
        for path in paths:
            if (
                path == Path(path.anchor)
                or not path.is_dir()
                or excluded(path, settings.exclusions, root)
            ):
                raise ValueError(f"Invalid or excluded watch directory: {path}")
            check_chain(path)
            self.observer.schedule(self, str(path), recursive=True)
        self.observer.start()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory or event.event_type not in {"created", "modified", "moved", "closed"}:
            return
        name = event.dest_path if event.event_type == "moved" else event.src_path
        path = Path(os.fsdecode(name))
        if excluded(path, self.settings.exclusions, self.root):
            return
        with self.lock:
            if path not in self.pending and len(self.pending) >= 512:
                self.pending.popitem(last=False)
                self.dropped += 1
            self.pending[path] = monotonic() + self.settings.debounce_ms / 1000
            self.pending.move_to_end(path)

    def drain(self, maximum: int = 12) -> list[Path]:
        now = monotonic()
        with self.lock:
            selected = [path for path, due in self.pending.items() if now >= due][:maximum]
            for path in selected:
                del self.pending[path]
        return selected

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join()
