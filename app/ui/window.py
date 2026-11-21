import html
import logging
from collections.abc import Callable, Iterable
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
    QThreadPool,
    QTimer,
)
from PySide6.QtGui import QCloseEvent, QIcon, QPixmap, QResizeEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.core.contracts import ScanResult
from app.core.settings import Settings
from app.database.history import History
from app.ml.model import Registry
from app.ml.schema import SCHEMAS
from app.monitoring.behavior import BehaviorSummary, import_report
from app.monitoring.files import FileMonitor
from app.monitoring.processes import ProcessSampler, inspect, system_events
from app.quarantine.service import Quarantine
from app.scanners.jobs import ScanSummary, candidates, run_scan
from app.scanners.static import Assessor
from app.ui.details import Details
from app.ui.operations import ProcessPanel, QuarantinePanel, SettingsPanel
from app.ui.tasks import Task
from app.ui.theme import apply_theme, colors
from app.ui.widgets import (
    ActivityChart,
    ScoreGauge,
    button,
    card,
    empty_state,
    icon,
    label,
    rows,
    table,
)

log = logging.getLogger(__name__)

_NAV = (
    ("Dashboard", "Dashboard"),
    ("Quick Scan", "Quick Scan"),
    ("Folder Scan", "Folder Scan"),
    ("Process Monitor", "Processes"),
    ("Quarantine", "Quarantine"),
    ("Threat History", "History"),
    ("Model Insights", "Models"),
    ("Settings", "Settings"),
)


def percentage(value: float | None) -> str:
    return "—" if value is None else f"{value:.0%}"


class ScanResults(QAbstractTableModel):
    HEADINGS = ("File", "Format", "Status", "Model score")
    LIMIT = 250

    def __init__(self, view: QTableView) -> None:
        super().__init__(view)
        self.records: list[ScanResult] = []

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADINGS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADINGS[section]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        item = self.records[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return (item.path, item.format, item.status, percentage(item.assessment.probability))[
                index.column()
            ]
        if role == Qt.ItemDataRole.ToolTipRole:
            if index.column() == 0:
                return f"<qt>{html.escape(item.path)}</qt>"
            if index.column() == 2 and item.message:
                return f"<qt>{html.escape(item.message)}</qt>"
            if index.column() == 3 and item.assessment.probability is None:
                return (
                    "Model scoring requires a supported executable."
                    if item.status == "Unsupported"
                    else f"<qt>{html.escape(item.assessment.reason)}</qt>"
                )
        return None

    def clear(self) -> None:
        self.beginResetModel()
        self.records.clear()
        self.endResetModel()

    def prepend(self, batch: list[ScanResult]) -> None:
        latest = list(reversed(batch[-self.LIMIT :]))
        if not latest:
            return
        keep = self.LIMIT - len(latest)
        if len(self.records) > keep:
            self.beginRemoveRows(QModelIndex(), keep, len(self.records) - 1)
            del self.records[keep:]
            self.endRemoveRows()
        self.beginInsertRows(QModelIndex(), 0, len(latest) - 1)
        self.records[:0] = latest
        self.endInsertRows()


class HistoryResults(QAbstractTableModel):
    COLUMNS = (
        ("File", "path"),
        ("UTC timestamp", "timestamp"),
        ("Format", "format"),
        ("Scan status", "status"),
        ("Model score", "probability"),
    )

    def __init__(self, view: QTableView) -> None:
        super().__init__(view)
        self.records: list[dict] = []

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section][0]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        key = self.COLUMNS[index.column()][1]
        value = self.records[index.row()][key]
        if role == Qt.ItemDataRole.DisplayRole:
            return percentage(value) if key == "probability" else value
        if role == Qt.ItemDataRole.ToolTipRole and key == "path":
            return f"<qt>{html.escape(value)}</qt>"
        return None

    def replace(self, records: list[dict]) -> None:
        self.beginResetModel()
        self.records = records
        self.endResetModel()


class ScanPage:
    def __init__(self, layout: QVBoxLayout, folder: bool) -> None:
        frame, actions = card()
        actions.setSpacing(12)
        self.select = button("Choose folder" if folder else "Choose file", primary=True)
        self.full = button("Scan home folder")
        self.recursive = QCheckBox("Include subfolders")
        self.recursive.setChecked(True)
        self.cancel = button("Cancel scan")
        self.cancel.setEnabled(False)
        tools = QHBoxLayout()
        tools.addWidget(self.select)
        if folder:
            tools.addWidget(self.full)
            tools.addWidget(self.recursive)
        tools.addStretch()
        tools.addWidget(self.cancel)
        actions.addLayout(tools)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        self.progress.setAccessibleName("Scan progress")
        self.status = label("Ready to scan", "muted")
        self.status.setWordWrap(True)
        actions.addWidget(self.status)
        actions.addWidget(self.progress)
        layout.addWidget(frame)

        heading = QHBoxLayout()
        heading.addWidget(label("Scan results", "section"))
        heading.addStretch()
        self.visible_count = label("", "muted")
        heading.addWidget(self.visible_count)
        layout.addLayout(heading)
        self.result_stack = QStackedWidget()
        self.empty = empty_state(
            "No results yet",
            "Results appear here as files are processed.",
        )
        self.result_stack.addWidget(self.empty)
        self.results = QTableView()
        self.results.setAccessibleName("Scan results")
        self.results_model = ScanResults(self.results)
        self.results.setModel(self.results_model)
        self.results.setAlternatingRowColors(True)
        self.results.setShowGrid(False)
        self.results.verticalHeader().hide()
        self.results.verticalHeader().setDefaultSectionSize(33)
        self.results.setWordWrap(False)
        self.results.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.results.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.results.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column, width in enumerate((82, 108, 110), 1):
            header.resizeSection(column, width)
        self.result_stack.addWidget(self.results)
        layout.addWidget(self.result_stack, 1)
        foot = QHBoxLayout()
        help_text = label(
            "Model scores require a supported executable and a matching local model.", "muted"
        )
        help_text.setWordWrap(True)
        foot.addWidget(help_text, 1)
        self.details = button("Open selected result")
        self.details.setEnabled(False)
        selection = self.results.selectionModel()
        selection.selectionChanged.connect(
            lambda *_: self.details.setEnabled(selection.hasSelection())
        )
        foot.addWidget(self.details)
        layout.addLayout(foot)
        self.records = self.results_model.records

    def clear(self) -> None:
        self.results_model.clear()
        self.result_stack.setCurrentWidget(self.empty)
        self.visible_count.clear()
        self.details.setEnabled(False)

    def update(self, batch: list[ScanResult]) -> None:
        self.results_model.prepend(batch)
        if self.records:
            self.result_stack.setCurrentWidget(self.results)
            self.visible_count.setText(f"Showing {len(self.records):,} latest results")


class Window(QMainWindow):
    def __init__(self, root: Path, settings: Settings, history: History) -> None:
        super().__init__()
        self.root = root
        self.settings = settings
        self.history = history
        self.assessor: Assessor | None = None
        self.model_loading = False
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(settings.scan_workers)
        self.tasks: set[Task] = set()
        self.scan_task: Task | None = None
        self.quarantine_service: Quarantine | None = None
        self.quarantine_busy = False
        self.monitor: FileMonitor | None = None
        self.watch_busy = False
        self.watch_task: Task | None = None
        self.watch_count = 0
        self.process_busy = False
        self.sampler: ProcessSampler | None = None
        self.closing = False
        self.setWindowTitle("SentinelAI")
        self.setMinimumSize(880, 620)
        self.resize(1200, 780)

        body = QWidget()
        shell = QVBoxLayout(body)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        top = QFrame()
        top.setObjectName("topBar")
        nav = QHBoxLayout(top)
        nav.setContentsMargins(24, 9, 24, 9)
        nav.setSpacing(4)
        assets = Path(__file__).resolve().parents[1] / "assets"
        brand = label("")
        brand.setAccessibleName("SentinelAI")
        artwork = QPixmap(str(assets / "wordmark.png")).scaledToHeight(
            72, Qt.TransformationMode.SmoothTransformation
        )
        artwork.setDevicePixelRatio(2)
        brand.setPixmap(artwork)
        self.setWindowIcon(QIcon(str(assets / "sentinelai.ico")))
        nav.addWidget(brand)
        nav.addSpacing(20)
        self.navigation = QButtonGroup(self)
        self.nav_buttons: dict[str, QPushButton] = {}
        for name, caption in _NAV[:-1]:
            nav.addWidget(self.nav_button(name, caption))
        nav.addStretch(1)
        nav.addWidget(self.nav_button(*_NAV[-1]))
        shell.addWidget(top)
        self.stack = QStackedWidget()
        shell.addWidget(self.stack, 1)
        self.setCentralWidget(body)
        self.toast = label("", "toast")
        self.toast.setParent(body)
        self.toast.setWordWrap(True)
        self.toast.setMaximumWidth(460)
        self.toast.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)
        self.pages: dict[str, QWidget] = {}
        self.layouts: dict[str, QVBoxLayout] = {}
        descriptions = {
            "Dashboard": "Scan activity and model availability on this device.",
            "Quick Scan": "Inspect a Windows PE or Linux ELF executable.",
            "Folder Scan": "Inspect Windows PE and Linux ELF executables in a folder.",
            "Process Monitor": "Inspect live process metadata with your permission.",
            "Quarantine": "Isolate or restore a file after reviewing and confirming the action.",
            "Threat History": "Search local scan history or look up an exact SHA-256 hash.",
            "Model Insights": "Review installed model versions, validation, and calibration.",
            "Settings": "Configure scan resources, monitoring, appearance, and local data retention.",
        }
        for name, _ in _NAV:
            self.page(name, descriptions[name])
        self.make_dashboard()
        self.quick = ScanPage(self.layouts["Quick Scan"], False)
        self.folder = ScanPage(self.layouts["Folder Scan"], True)
        self.quick.select.clicked.connect(self.pick_file)
        self.folder.select.clicked.connect(self.pick_folder)
        self.folder.full.clicked.connect(self.scan_home)
        for page in (self.quick, self.folder):
            page.cancel.clicked.connect(self.cancel_scan)
            page.details.clicked.connect(lambda _checked=False, page=page: self.scan_detail(page))
            page.results.doubleClicked.connect(lambda _index, page=page: self.scan_detail(page))
        self.make_history()
        self.make_models()
        self.make_operations()
        self.go("Dashboard")
        self.statusBar().addPermanentWidget(label("Offline workspace", "muted"))
        self.statusBar().showMessage("Ready")
        self.reload_models()

    def nav_button(self, name: str, caption: str) -> QPushButton:
        item = button(caption)
        item.setAccessibleName(name)
        if caption != name:
            item.setToolTip(name)
        item.setProperty("nav", True)
        item.setCheckable(True)
        self.navigation.addButton(item)
        self.nav_buttons[name] = item
        item.clicked.connect(lambda _checked=False: self.go(name))
        return item

    def make_operations(self) -> None:
        self.settings_panel = SettingsPanel(self.settings)
        self.layouts["Settings"].addWidget(self.settings_panel, 1)
        self.settings_panel.save.clicked.connect(self.save_settings)
        self.settings_panel.watch.clicked.connect(self.toggle_watch)
        self.watch_timer = QTimer(self)
        self.watch_timer.setInterval(500)
        self.watch_timer.timeout.connect(self.watch_tick)

        self.process_panel = ProcessPanel()
        self.layouts["Process Monitor"].addWidget(self.process_panel, 1)
        self.process_panel.toggle.clicked.connect(self.toggle_process)
        self.process_panel.inspect.clicked.connect(self.process_scan)
        self.process_panel.event_lookup.clicked.connect(self.event_lookup)
        self.process_panel.import_report.clicked.connect(self.behavior_lookup)
        self.process_timer = QTimer(self)
        self.process_timer.setInterval(self.settings.process_interval_ms)
        self.process_timer.timeout.connect(self.process_tick)

        self.quarantine_panel = QuarantinePanel()
        self.layouts["Quarantine"].addWidget(self.quarantine_panel, 1)
        self.quarantine_panel.restore.clicked.connect(lambda: self.restore_selected(False))
        self.quarantine_panel.restore_as.clicked.connect(lambda: self.restore_selected(True))
        self.quarantine_panel.inspect.clicked.connect(self.quarantine_details)

        def service(_cancel: Event, _emit: Callable) -> Quarantine:
            quarantine = Quarantine(self.root, self.history)
            quarantine.recover()
            return quarantine

        def ready(quarantine: Quarantine) -> None:
            self.quarantine_service = quarantine
            self.refresh_quarantine()

        self.launch(
            service,
            ready,
            fail=lambda error: self.quarantine_panel.status.setText(
                f"Quarantine unavailable · {error}"
            ),
        )

    def show_text(self, title: str, text: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(690, 495)
        layout = QVBoxLayout(dialog)
        body = QPlainTextEdit()
        body.setPlainText(text)
        body.setReadOnly(True)
        layout.addWidget(body)
        close = button("Close")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)
        dialog.exec()

    def save_settings(self) -> None:
        try:
            value = self.settings_panel.values()
            if any(not Path(folder).is_absolute() for folder in value.watch_dirs):
                raise ValueError("Watch folders must be absolute paths.")
            value.save(self.root)
        except (OSError, ValueError) as exc:
            self.failure(str(exc))
            return
        watch = self.monitor
        previous = self.settings
        self.settings = value
        self.pool.setMaxThreadCount(value.scan_workers)
        self.process_timer.setInterval(value.process_interval_ms)
        application = QApplication.instance()
        if isinstance(application, QApplication):
            apply_theme(application, value.theme)
        if value.theme != previous.theme:
            self.update_metric_icons()
        self.chart.theme = value.theme
        self.chart.update()
        self.coverage.theme = value.theme
        self.coverage.update()
        self.settings_panel.monitor_status.setText(
            "Settings saved · File monitoring is off" if watch is None else "Settings saved"
        )
        if watch and any(
            getattr(previous, name) != getattr(value, name)
            for name in ("watch_dirs", "exclusions", "max_mib", "debounce_ms", "scan_duty_percent")
        ):
            self.stop_watch()
            if previous.watch_dirs == value.watch_dirs:
                self.start_watch()
        if isinstance(self.assessor, Registry):
            self.assessor.threads = value.model_threads
        self.launch(
            lambda _cancel, _emit: self.history.prune(value.retention_days),
            lambda _result: self.refresh_visible_history(),
        )
        self.notify("Settings saved")

    def toggle_watch(self) -> None:
        if self.monitor is not None:
            self.stop_watch()
        elif self.confirm(
            "Start filesystem monitoring?",
            "Watch and scan changed files in the configured directories during this "
            "session. Scan records are stored locally.",
        ):
            self.start_watch()

    def start_watch(self) -> None:
        try:
            self.monitor = FileMonitor(self.settings, self.root)
        except (OSError, RuntimeError, ValueError) as exc:
            self.settings_panel.monitor_status.setText(f"Monitoring unavailable · {exc}")
            return
        self.watch_count = 0
        self.settings_panel.watch.setText("Stop file monitoring")
        self.watch_timer.start()

    def stop_watch(self) -> None:
        self.watch_timer.stop()
        if self.watch_task is not None:
            self.watch_task.cancel.set()
        monitor, self.monitor = self.monitor, None
        if monitor:
            monitor.stop()
        self.settings_panel.watch.setText("Start file monitoring")
        self.settings_panel.monitor_status.setText("File monitoring is off")

    def watch_tick(self) -> None:
        monitor = self.monitor
        if monitor is None:
            return
        drops = monitor.dropped + monitor.queue.dropped
        self.settings_panel.monitor_status.setText(
            f"Monitoring active · {self.watch_count:,} processed · {drops:,} dropped due to load"
        )
        if self.watch_busy or self.scan_task:
            return
        targets = monitor.drain()
        if not targets:
            return
        self.watch_busy = True
        settings, assessor = self.settings, self.assessor

        def done(summary: ScanSummary) -> None:
            if self.monitor is monitor:
                self.watch_count += summary.total
                self.refresh_visible_history()
                if summary.flagged:
                    self.notify(f"File monitoring found {summary.flagged} elevated model scores.")

        def finished() -> None:
            self.watch_busy = False
            self.watch_task = None

        self.watch_task = self.launch(
            lambda cancel, _emit: run_scan(
                targets,
                settings,
                self.root,
                cancel,
                lambda result: self.history.record(result, "Watch"),
                assessor,
            ),
            done,
            finished=finished,
            fail=lambda message: self.notify(message),
        )

    def toggle_process(self) -> None:
        if self.sampler is not None:
            self.sampler = None
            self.process_timer.stop()
            self.process_panel.tree.clear()
            self.process_panel.toggle.setText("Start monitor")
            self.process_panel.status.setText("Process collection is off")
        elif self.confirm(
            "Start process monitoring?",
            "Sample readable process names, parents, CPU, and memory while this session is active.",
        ):
            self.sampler = ProcessSampler()
            self.process_panel.toggle.setText("Stop monitor")
            self.process_timer.start()
            self.process_tick()

    def process_tick(self) -> None:
        sampler = self.sampler
        if sampler is None or self.process_busy:
            return
        self.process_busy = True

        def show(sample: tuple) -> None:
            if self.sampler is sampler:
                self.process_panel.show_processes(*sample)

        def finished() -> None:
            self.process_busy = False

        self.launch(
            lambda cancel, _emit: sampler.sample(cancel),
            show,
            finished=finished,
            fail=lambda error: self.process_panel.status.setText(error),
        )

    def process_scan(self) -> None:
        selection = self.process_panel.selection()
        if selection is None:
            return
        self.go("Quick Scan")
        self.start_scan(
            self.quick, lambda _cancel: [inspect(*selection)], "Selected process", one=True
        )

    def event_lookup(self) -> None:
        if not self.confirm(
            "Read system event metadata?",
            "Read a bounded set of recent event metadata available to this account.",
        ):
            return
        self.process_panel.event_lookup.setEnabled(False)

        def done(data: tuple[list[tuple[str, str, str]], str]) -> None:
            events, status = data
            display = "\n".join("  ·  ".join(row) for row in events)
            self.show_text("System event metadata", f"{status}\n\n{display}")

        self.launch(
            lambda _cancel, _emit: system_events(),
            done,
            finished=lambda: self.process_panel.event_lookup.setEnabled(True),
        )

    def behavior_lookup(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import sandbox behavior report", "", "JSON reports (*.json)"
        )
        if not filename:
            return
        self.process_panel.import_report.setEnabled(False)

        def done(report: BehaviorSummary) -> None:
            limits = "Report reached an import limit.\n" if report.truncated else ""
            data = "\n".join(
                f"{kind.capitalize()}  {count:,}" for kind, count in report.counts.items()
            )
            self.show_text(
                "Imported behavioral summary",
                f"{report.source}\n{report.processes:,} process streams · "
                f"{report.events:,} events\n{limits}"
                "Behavior classifier unavailable. The counts describe imported data.\n\n"
                f"{data}",
            )

        self.launch(
            lambda _cancel, _emit: import_report(Path(filename)),
            done,
            finished=lambda: self.process_panel.import_report.setEnabled(True),
        )

    def refresh_quarantine(self) -> None:
        service = self.quarantine_service
        if service is None:
            return
        panel = self.quarantine_panel
        panel.entries = service.items()
        panel.status.setText(f"{len(panel.entries):,} recent manifest entries")
        rows(
            panel.grid,
            [
                (item["original"], item["state"], item["timestamp"], item["size"])
                for item in panel.entries
            ],
        )
        panel.selection_changed()

    def quarantine_selected(self) -> None:
        service = self.quarantine_service
        item = self.selected_history()
        if service is None or self.quarantine_busy or item is None:
            return
        if not item["sha256"]:
            self.failure("The selected result has no verified file fingerprint.")
            return
        path = Path(item["path"])
        if not self.confirm(
            "Quarantine this file?", f"Move this file into private local storage?\n\n{path}"
        ):
            return
        self.run_quarantine(
            lambda: service.store(path, item["sha256"], confirmed=True),
            "File isolated. Open Quarantine to restore it.",
        )

    def restore_selected(self, alternate: bool) -> None:
        service, item = self.quarantine_service, self.quarantine_panel.selection()
        if service is None or item is None or self.quarantine_busy:
            return
        target = Path(item["original"])
        if alternate:
            name, accepted = QInputDialog.getText(
                self,
                "Restore with a different name",
                "New filename in the original directory",
                text=target.name,
            )
            if not accepted:
                return
            if not name.strip() or name in (".", "..") or any(c in name for c in ("/", "\\", ":")):
                self.failure("Enter a filename without directory components.")
                return
            target = target.with_name(name)
        if self.confirm(
            "Restore this file?", f"Move this file out of private storage?\n\n{target}"
        ):
            self.run_quarantine(
                lambda: service.restore(item["id"], target, confirmed=True), "File restored"
            )

    def run_quarantine(self, work: Callable, message: str) -> None:
        self.quarantine_busy = True

        def finished() -> None:
            self.quarantine_busy = False
            self.refresh_quarantine()

        self.launch(
            lambda _cancel, _emit: work(), lambda _result: self.notify(message), finished=finished
        )

    def quarantine_details(self) -> None:
        item = self.quarantine_panel.selection()
        if item:
            self.show_text(
                "Quarantine manifest entry",
                "\n".join(
                    f"{name}  {item[key] or '—'}"
                    for key, name in (
                        ("id", "ID"),
                        ("original", "Original"),
                        ("destination", "Destination"),
                        ("sha256", "SHA-256"),
                        ("state", "State"),
                        ("note", "Note"),
                    )
                ),
            )

    def make_models(self) -> None:
        layout = self.layouts["Model Insights"]
        actions = QHBoxLayout()
        reload_button = button("Reload local models", primary=True)
        reload_button.clicked.connect(self.reload_models)
        actions.addWidget(reload_button)
        actions.addStretch()
        layout.addLayout(actions)
        self.model_details = QPlainTextEdit()
        self.model_details.setReadOnly(True)
        layout.addWidget(self.model_details, 1)

    def reload_models(self) -> None:
        if self.model_loading:
            return
        self.model_loading = True
        self.model_details.setPlainText("Checking local model packages…")
        directory, threads = self.root / "models", self.settings.model_threads

        def done(registry: Registry) -> None:
            registry.threads = self.settings.model_threads
            self.assessor = registry
            formats = ", ".join(registry.models)
            self.model_state.setText(
                f"Local models ready · {formats}"
                if formats
                else "Static analysis ready · Model assessments unavailable"
            )
            paragraphs = [f"Local bundles  {directory}"]
            for kind, schema in SCHEMAS.items():
                model = registry.models.get(kind)
                if model is None:
                    paragraphs.append(f"{kind}  ·  {schema.id}\n{registry.reasons[kind]}")
                    continue
                meta = model.manifest
                metrics = meta["metrics"]
                matrix = metrics["confusion_matrix"]
                accuracy = (matrix[0][0] + matrix[1][1]) / sum(sum(row) for row in matrix)
                paragraphs.append(
                    f"{kind}  ·  {model.schema.id}  ·  {meta['version']}\n"
                    f"Dataset provenance  {meta['provenance']}\n"
                    f"Evaluation splits  {meta['splits']}\n"
                    f"Calibration  Platt scaling on the validation partition · "
                    f"Brier score {metrics['brier_score']:.4f}\n"
                    f"Accuracy {accuracy:.2%} · Precision {metrics['precision']:.2%} · "
                    f"Recall {metrics['recall']:.2%} · "
                    f"F1 {metrics['f1']:.3f} · ROC-AUC {metrics['roc_auc']:.3f} · "
                    f"FPR {metrics['false_positive_rate']:.2%}\n"
                    f"Held-out confusion matrix (TN/FP, FN/TP)  {metrics['confusion_matrix']}\n"
                    f"{meta['limitations']}"
                )
            self.model_details.setPlainText("\n\n".join(paragraphs))

        def finished() -> None:
            self.model_loading = False

        self.launch(lambda _cancel, _emit: Registry(directory, threads), done, finished=finished)

    def page(self, name: str, description: str) -> QVBoxLayout:
        page = QWidget()
        page.setObjectName("workspace")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(12)
        header = QFrame()
        header.setObjectName("pageHeader")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 9)
        header_layout.setSpacing(4)
        heading = label(name, "title")
        heading.setAccessibleName(name)
        header_layout.addWidget(heading)
        subtitle = label(description, "muted")
        subtitle.setWordWrap(True)
        header_layout.addWidget(subtitle)
        layout.addWidget(header)
        self.stack.addWidget(page)
        self.pages[name] = page
        self.layouts[name] = layout
        return layout

    def go(self, name: str) -> None:
        if name != "Threat History" and self.history_visible():
            self.search_delay.stop()
            self.history_pending = False
            if self.history_task is not None:
                self.history_task.cancel.set()
        self.nav_buttons[name].setChecked(True)
        self.stack.setCurrentWidget(self.pages[name])
        if name == "Dashboard":
            self.refresh_dashboard()
        elif name == "Threat History":
            self.refresh_history()

    def make_dashboard(self) -> None:
        layout = self.layouts["Dashboard"]
        counts = QHBoxLayout()
        counts.setSpacing(12)
        self.metrics: dict[str, QLabel] = {}
        self.metric_icons: list[tuple[QLabel, str, str]] = []
        for key, caption, symbol, color in (
            ("scans", "Files processed", "file", "accent"),
            ("analyzed", "Executables analyzed", "shield", "bar"),
            ("elevated", "Elevated scores", "activity", "violet"),
            ("unique_files", "Distinct hashes", "history", "muted"),
        ):
            metric, area = card()
            area.setContentsMargins(14, 10, 14, 11)
            area.setSpacing(3)
            heading = QHBoxLayout()
            heading.addWidget(label(caption, "muted"))
            heading.addStretch()
            image = label("")
            image.setFixedSize(17, 17)
            heading.addWidget(image)
            area.addLayout(heading)
            self.metric_icons.append((image, symbol, color))
            self.metrics[key] = label("0", "metric")
            area.addWidget(self.metrics[key])
            counts.addWidget(metric, 1)
        self.update_metric_icons()
        layout.addLayout(counts)

        panels = QHBoxLayout()
        panels.setSpacing(12)
        activity, plot = card()
        chart_heading = QHBoxLayout()
        chart_heading.addWidget(label("Scan activity", "section"))
        chart_heading.addStretch()
        chart_heading.addWidget(label("Last 7 days", "muted"))
        plot.addLayout(chart_heading)
        self.chart = ActivityChart(self.settings.theme)
        plot.addWidget(self.chart, 1)
        panels.addWidget(activity, 5)

        coverage_card, coverage_box = card()
        coverage_box.addWidget(label("Analysis coverage", "section"))
        self.coverage = ScoreGauge(self.settings.theme, None, color="violet")
        self.coverage.setAccessibleName("Share of entries analyzed")
        coverage_box.addWidget(self.coverage, 1, Qt.AlignmentFlag.AlignCenter)
        self.coverage_summary = label("", "muted")
        self.coverage_summary.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.coverage_summary.setWordWrap(True)
        coverage_box.addWidget(self.coverage_summary)
        panels.addWidget(coverage_card, 3)

        scan_card, scan_box = card()
        scan_box.addWidget(label("Start a scan", "section"))
        self.model_state = label("Checking local models…", "muted")
        self.model_state.setWordWrap(True)
        scan_box.addWidget(self.model_state)
        scan_box.addStretch()
        scan = button("Scan a file", primary=True)
        scan.clicked.connect(self.dashboard_pick)
        directory = button("Scan a folder")
        directory.clicked.connect(lambda: self.go("Folder Scan"))
        scan_box.addWidget(scan)
        scan_box.addWidget(directory)
        panels.addWidget(scan_card, 3)
        layout.addLayout(panels)

        activity_row = QHBoxLayout()
        activity_row.addWidget(label("Recent scans", "section"))
        activity_row.addStretch()
        history = button("View history")
        history.clicked.connect(lambda: self.go("Threat History"))
        activity_row.addWidget(history)
        recent_card, recent_box = card()
        recent_box.setContentsMargins(12, 9, 12, 12)
        recent_box.addLayout(activity_row)
        self.recent = table(["File", "Format", "Status", "Model score"])
        self.recent.cellDoubleClicked.connect(
            lambda row, _: self.open_history(self.recent_rows[row]["id"])
        )
        self.recent_stack = QStackedWidget()
        self.recent_empty = empty_state(
            "No scan history",
            "New scans will appear here.",
        )
        self.recent_stack.addWidget(self.recent_empty)
        self.recent_stack.addWidget(self.recent)
        recent_box.addWidget(self.recent_stack, 1)
        layout.addWidget(recent_card, 1)
        self.recent_rows: list[dict] = []

    def update_metric_icons(self) -> None:
        palette = colors(self.settings.theme)
        for image, symbol, color in self.metric_icons:
            image.setPixmap(icon(symbol, palette[color], 17))

    def dashboard_pick(self) -> None:
        self.go("Quick Scan")
        self.pick_file()

    def refresh_dashboard(self) -> None:
        totals, data = self.history.dashboard()
        for key, widget in self.metrics.items():
            widget.setText(f"{(totals[key] or 0):,}")
        self.chart.set_counts(data)
        processed = totals["scans"] or 0
        analyzed = totals["analyzed"] or 0
        self.coverage.set_score(analyzed / processed if processed else None)
        self.coverage_summary.setText(
            f"{analyzed:,} of {processed:,} entries analyzed" if processed else "No scans recorded"
        )
        self.recent_rows = self.history.recent(limit=8)
        self.recent_stack.setCurrentWidget(self.recent if self.recent_rows else self.recent_empty)
        rows(
            self.recent,
            [
                (item["path"], item["format"], item["status"], percentage(item["probability"]))
                for item in self.recent_rows
            ],
        )

    def make_history(self) -> None:
        self.history_pool = QThreadPool(self)
        self.history_pool.setMaxThreadCount(1)
        self.history_task: Task | None = None
        self.history_pending = False
        layout = self.layouts["Threat History"]
        search = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search file path")
        self.query.setAccessibleName("Search file path")
        self.hash_query = QLineEdit()
        self.hash_query.setPlaceholderText("Exact SHA-256")
        self.hash_query.setAccessibleName("Exact SHA-256")
        self.hash_query.setMaxLength(64)
        self.status_query = QComboBox()
        self.status_query.addItems(
            ["All statuses", "Analyzed", "Unsupported", "Malformed", "Skipped", "Error"]
        )
        search.addWidget(self.query, 2)
        search.addWidget(self.hash_query, 2)
        search.addWidget(self.status_query, 1)
        layout.addLayout(search)
        self.history_status = label("", "muted")
        self.history_status.setWordWrap(True)
        layout.addWidget(self.history_status)
        self.history_grid = QTableView()
        self.history_grid.setAccessibleName("History results")
        self.history_model = HistoryResults(self.history_grid)
        self.history_grid.setModel(self.history_model)
        self.history_grid.setAlternatingRowColors(True)
        self.history_grid.setShowGrid(False)
        self.history_grid.verticalHeader().hide()
        self.history_grid.verticalHeader().setDefaultSectionSize(33)
        self.history_grid.setWordWrap(False)
        self.history_grid.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.history_grid.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_grid.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.history_grid.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column, width in enumerate((205, 78, 110, 110), 1):
            header.resizeSection(column, width)
        self.history_grid.doubleClicked.connect(lambda _index: self.history_detail())
        layout.addWidget(self.history_grid, 1)
        actions = QHBoxLayout()
        detail = button("Open selected result")
        detail.clicked.connect(self.history_detail)
        isolate = button("Quarantine selected file…")
        isolate.clicked.connect(self.quarantine_selected)
        selection = self.history_grid.selectionModel()
        for action in (detail, isolate):
            action.setEnabled(False)

        def selection_changed() -> None:
            available = self.selected_history() is not None
            detail.setEnabled(available)
            isolate.setEnabled(available)

        selection.selectionChanged.connect(selection_changed)
        self.history_model.modelReset.connect(selection_changed)
        actions.addWidget(detail)
        actions.addWidget(isolate)
        actions.addStretch()
        layout.addLayout(actions)
        self.search_delay: QTimer = QTimer(self)
        self.search_delay.setSingleShot(True)
        self.search_delay.setInterval(180)
        self.search_delay.timeout.connect(self.refresh_history)
        self.query.textChanged.connect(self.schedule_history)
        self.hash_query.textChanged.connect(self.schedule_history)
        self.status_query.currentIndexChanged.connect(self.schedule_history)

    def history_visible(self) -> bool:
        return self.stack.currentWidget() == self.pages["Threat History"]

    def schedule_history(self) -> None:
        if self.history_task is not None:
            self.history_task.cancel.set()
        if self.history_model.records:
            self.history_model.replace([])
        self.history_status.setText("Loading history…")
        if self.history_visible():
            self.search_delay.start()

    def refresh_history(self) -> None:
        if self.closing or not self.history_visible() or self.search_delay.isActive():
            return
        if self.history_task is not None:
            self.history_pending = True
            return
        self.history_pending = False
        filters = (
            self.query.text(),
            self.status_query.currentText() if self.status_query.currentIndex() else "",
            self.hash_query.text().strip().lower(),
        )
        if not self.history_model.records:
            self.history_status.setText("Loading history…")

        def current() -> bool:
            return self.history_visible() and not self.closing and not task.cancel.is_set()

        def done(records: list[dict]) -> None:
            if not current():
                return
            if records != self.history_model.records:
                item = self.selected_history()
                self.history_model.replace(records)
                if item is not None:
                    for index, record in enumerate(records):
                        if record["id"] == item["id"]:
                            self.history_grid.selectRow(index)
                            break
            self.history_status.setText(
                f"Showing {len(records):,} latest results" if records else "No matching scans"
            )

        def failed(error: str) -> None:
            if current():
                self.history_status.setText(f"Could not load history · {error}")

        def finished() -> None:
            self.history_task = None
            if self.history_pending:
                self.refresh_history()

        task: Task = self.launch(
            lambda cancel, _emit: self.history.recent(*filters, cancel=cancel),
            done,
            finished=finished,
            fail=failed,
            pool=self.history_pool,
        )
        self.history_task = task

    def selected_history(self) -> dict | None:
        selected = self.history_grid.selectionModel().selectedRows()
        return self.history_model.records[selected[0].row()] if selected else None

    def history_detail(self) -> None:
        item = self.selected_history()
        if item is not None:
            self.open_history(item["id"])

    def open_history(self, scan_id: int) -> None:
        data = self.history.detail(scan_id)
        if data:
            Details(data, self.settings.theme, self).exec()

    def scan_detail(self, page: ScanPage) -> None:
        row = page.results.currentIndex().row()
        if 0 <= row < len(page.records):
            Details(page.records[row].to_dict(), self.settings.theme, self).exec()

    def pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to scan")
        if path:
            self.start_scan(self.quick, [Path(path)], "Single file", one=True)

    def pick_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if path:
            self.directory_scan(Path(path), self.folder.recursive.isChecked(), "Folder")

    def scan_home(self) -> None:
        if self.confirm(
            "Scan home folder?",
            "Scan accessible files and subfolders in your home "
            "folder. Your exclusions and size limit apply.",
        ):
            self.directory_scan(Path.home(), True, "Home")

    def directory_scan(self, path: Path, recursive: bool, origin: str) -> None:
        settings = self.settings
        self.start_scan(
            self.folder,
            lambda cancel: candidates(path, recursive, settings, self.root, cancel),
            origin,
            one=False,
        )

    def start_scan(
        self,
        page: ScanPage,
        paths: Iterable[Path | ScanResult] | Callable[[Event], Iterable[Path | ScanResult]],
        origin: str,
        *,
        one: bool,
    ) -> None:
        if self.scan_task is not None:
            self.notify("A manual scan is already running.")
            return
        settings, assessor = self.settings, self.assessor

        def work(cancel: Event, emit: Callable[[Any], None]) -> ScanSummary:
            pending: list[ScanResult] = []
            last = monotonic()
            count = 0

            def record(result: ScanResult) -> None:
                nonlocal last, count
                self.history.record(result, origin)
                count += 1
                pending.append(result)
                if monotonic() - last > 0.35:
                    emit((count, pending[-60:]))
                    pending.clear()
                    last = monotonic()
                elif len(pending) > 100:
                    del pending[:-60]

            result = run_scan(
                paths(cancel) if callable(paths) else paths,
                settings,
                self.root,
                cancel,
                record,
                assessor,
                parallel=not one,
            )
            if pending:
                emit((count, pending[:]))
            return result

        def update(value: tuple[int, list[ScanResult]]) -> None:
            count, batch = value
            page.update(batch)
            page.status.setText(f"Processed {count:,} file entries")

        def done(summary: ScanSummary) -> None:
            state = "Cancelled" if summary.cancelled else "Completed"
            suffix = " · Scan entry limit reached" if summary.capped else ""
            message = (
                f"{state} · {summary.total:,} processed · {summary.analyzed:,} analyzed"
                f" · {summary.issues:,} issues or skips · {summary.flagged:,} elevated{suffix}"
            )
            page.progress.setRange(0, 1)
            page.progress.setValue(int(not summary.cancelled))
            page.status.setText(message)
            self.notify(message)
            self.refresh_visible_history()

        def finished() -> None:
            self.scan_task = None
            for entry in (self.quick, self.folder):
                entry.select.setEnabled(True)
                entry.full.setEnabled(True)
                entry.cancel.setEnabled(False)
            if page.progress.maximum() == 0:
                page.progress.setRange(0, 1)
                page.progress.setValue(0)

        page.clear()
        page.status.setText("Scanning file…" if one else "Discovering and scanning files…")
        page.progress.setRange(0, 0)
        for entry in (self.quick, self.folder):
            entry.select.setEnabled(False)
            entry.full.setEnabled(False)
        page.cancel.setEnabled(True)
        self.scan_task = self.launch(
            work,
            done,
            progress=update,
            finished=finished,
            fail=lambda error: page.status.setText(f"Scan failed · {error}"),
        )

    def cancel_scan(self) -> None:
        if self.scan_task is not None:
            self.scan_task.cancel.set()
            self.notify("Cancelling the scan…")

    def launch(
        self,
        work: Callable[[Event, Callable[[Any], None]], Any],
        done: Callable,
        *,
        progress: Callable | None = None,
        finished: Callable | None = None,
        fail: Callable[[str], None] | None = None,
        pool: QThreadPool | None = None,
    ) -> Task:
        task = Task(work)
        self.tasks.add(task)
        task.signals.done.connect(done, Qt.ConnectionType.QueuedConnection)
        task.signals.failed.connect(fail or self.failure, Qt.ConnectionType.QueuedConnection)
        if progress is not None:
            task.signals.progress.connect(progress, Qt.ConnectionType.QueuedConnection)

        def cleaned() -> None:
            self.tasks.discard(task)
            if finished is not None:
                finished()

        task.signals.finished.connect(cleaned, Qt.ConnectionType.QueuedConnection)
        (pool if pool is not None else self.pool).start(task)
        return task

    def refresh_visible_history(self) -> None:
        page = self.stack.currentWidget()
        if page == self.pages["Dashboard"]:
            self.refresh_dashboard()
        elif page == self.pages["Threat History"]:
            self.refresh_history()

    def notify(self, message: str) -> None:
        if self.settings.notifications:
            self.statusBar().showMessage(message, 8000)
            self.toast.setText(message[:240])
            self.toast.adjustSize()
            self.position_toast()
            self.toast.raise_()
            self.toast.show()
            self.toast_timer.start(4200)

    def position_toast(self) -> None:
        area = self.centralWidget()
        self.toast.move(
            area.width() - self.toast.width() - 24, area.height() - self.toast.height() - 16
        )

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if hasattr(self, "toast") and self.toast.isVisible():
            self.position_toast()

    def failure(self, message: str) -> None:
        QMessageBox.warning(self, "SentinelAI", html.escape(message))

    def confirm(self, title: str, message: str) -> bool:
        dialog = QMessageBox(
            QMessageBox.Icon.Question,
            title,
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            self,
        )
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(message)
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self.closing:
            self.closing = True
            self.stop_watch()
            self.process_timer.stop()
        for task in self.tasks:
            task.cancel.set()
        if self.tasks:
            self.statusBar().showMessage("Waiting for background work to finish…")
            event.ignore()
            QTimer.singleShot(150, self.close)
            return
        event.accept()
