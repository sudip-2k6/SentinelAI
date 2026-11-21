from types import SimpleNamespace
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QPlainTextEdit,
    QScrollArea,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.settings import Settings
from app.monitoring.processes import ProcessRow
from app.ui.widgets import button, card, label, table


class SettingsPanel(QWidget):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.controls = SimpleNamespace()
        self.controls.theme = QComboBox()
        self.controls.theme.addItems(["Dark", "Light"])
        self.controls.theme.setCurrentText(settings.theme)
        self.controls.notifications = QCheckBox("Show in-app notifications")
        self.controls.notifications.setChecked(settings.notifications)
        self.controls.exclusions = self.lines(settings.exclusions, "Exclusion patterns")
        self.controls.watch_dirs = self.lines(settings.watch_dirs, "Watched directories")
        inner = QWidget()
        sections = QVBoxLayout(inner)
        sections.setContentsMargins(0, 0, 0, 0)
        sections.setSpacing(12)
        appearance = self.section(sections, "Appearance & notifications")
        appearance.addRow("Theme", self.controls.theme)
        appearance.addRow("Notifications", self.controls.notifications)

        scan = self.section(sections, "Scanning")
        history = self.section(sections, "History")
        monitoring = self.section(sections, "Monitoring")
        for form, fields in (
            (
                scan,
                (
                    ("scan_workers", "Worker limit", 1, 4, ""),
                    ("model_threads", "Inference thread limit", 1, 4, ""),
                    ("max_mib", "Maximum file size", 1, 128, " MiB"),
                    ("scan_duty_percent", "Scan duty target", 10, 100, "%"),
                ),
            ),
            (history, (("retention_days", "History retention", 1, 3650, " days"),)),
            (
                monitoring,
                (
                    ("debounce_ms", "Watch debounce", 250, 15000, " ms"),
                    ("process_interval_ms", "Process sampling interval", 1000, 30000, " ms"),
                ),
            ),
        ):
            for key, caption, low, high, unit in fields:
                control = QSpinBox()
                control.setRange(low, high)
                control.setValue(getattr(settings, key))
                control.setSuffix(unit)
                control.setAccessibleName(caption)
                setattr(self.controls, key, control)
                form.addRow(caption, control)
        scan.addRow("Exclusion globs (one per line)", self.controls.exclusions)
        monitoring.addRow("Watch folders (absolute paths, one per line)", self.controls.watch_dirs)
        sections.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll, 1)
        tools = QHBoxLayout()
        self.save = button("Save settings", primary=True)
        self.watch = button("Start file monitoring")
        tools.addWidget(self.save)
        tools.addWidget(self.watch)
        tools.addStretch()
        outer.addLayout(tools)
        self.monitor_status = label("File monitoring is off", "muted")
        self.monitor_status.setWordWrap(True)
        outer.addWidget(self.monitor_status)

    @staticmethod
    def section(layout: QVBoxLayout, title: str) -> QFormLayout:
        frame, box = card()
        box.addWidget(label(title, "section"))
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setHorizontalSpacing(20)
        form.setVerticalSpacing(8)
        box.addLayout(form)
        layout.addWidget(frame)
        return form

    @staticmethod
    def lines(values: list[str], name: str) -> QPlainTextEdit:
        field = QPlainTextEdit("\n".join(values))
        field.setAccessibleName(name)
        field.setFixedHeight(80)
        return field

    def values(self) -> Settings:
        fields: dict[str, Any] = {}
        for key, control in vars(self.controls).items():
            if isinstance(control, QSpinBox):
                fields[key] = control.value()
            elif isinstance(control, QComboBox):
                fields[key] = control.currentText()
            elif isinstance(control, QCheckBox):
                fields[key] = control.isChecked()
            else:
                fields[key] = [
                    line.strip() for line in control.toPlainText().splitlines() if line.strip()
                ]
        value = Settings(**fields)
        value.validate()
        return value


class ProcessPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        actions = QHBoxLayout()
        self.toggle = button("Start monitor", primary=True)
        self.inspect = button("Scan selected")
        self.inspect.setToolTip("Scan the executable for the selected process")
        self.event_lookup = button("System events")
        self.event_lookup.setToolTip("Read system event metadata")
        self.import_report = button("Import report")
        self.import_report.setToolTip("Import a behavior report")
        self.inspect.setEnabled(False)
        for action in (self.toggle, self.inspect, self.event_lookup, self.import_report):
            actions.addWidget(action)
        actions.addStretch()
        layout.addLayout(actions)
        self.status = label("Process collection is off", "muted")
        layout.addWidget(self.status)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Process", "PID", "CPU", "Resident memory"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.tree, 1)
        self.tree.itemSelectionChanged.connect(
            lambda: self.inspect.setEnabled(self.tree.currentItem() is not None)
        )

    def show_processes(self, processes: list[ProcessRow], denied: int) -> None:
        current = self.tree.currentItem()
        selected = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        expanded = set()
        for item in self.tree.findItems(
            "*", Qt.MatchFlag.MatchWildcard | Qt.MatchFlag.MatchRecursive
        ):
            if item.isExpanded():
                expanded.add(item.data(0, Qt.ItemDataRole.UserRole))
        self.tree.setUpdatesEnabled(False)
        self.tree.clear()
        nodes: dict[int, QTreeWidgetItem] = {}
        index = {item.pid: item for item in processes}
        for record in processes:
            node = QTreeWidgetItem(
                [
                    record.name,
                    str(record.pid),
                    f"{record.cpu:.1f}%",
                    f"{record.memory / 1024**2:.1f} MiB",
                ]
            )
            node.setData(0, Qt.ItemDataRole.UserRole, (record.pid, record.started))
            nodes[record.pid] = node
        roots = []
        for record in processes:
            node = nodes[record.pid]
            parent = index.get(record.parent)
            if (
                parent is not None
                and parent.pid != record.pid
                and (parent.started, parent.pid) < (record.started, record.pid)
            ):
                nodes[parent.pid].addChild(node)
            else:
                roots.append(node)
        self.tree.addTopLevelItems(roots)
        for record in processes:
            marker = (record.pid, record.started)
            if marker in expanded:
                nodes[record.pid].setExpanded(True)
            if marker == selected:
                self.tree.setCurrentItem(nodes[record.pid])
        self.tree.setUpdatesEnabled(True)
        self.status.setText(
            f"{len(processes):,} visible processes · {denied:,} inaccessible or "
            "exited · First CPU sample starts at 0%"
        )

    def selection(self) -> tuple[int, float] | None:
        current = self.tree.currentItem()
        if current is None:
            return None
        pid, started = current.data(0, Qt.ItemDataRole.UserRole)
        return int(pid), float(started)


class QuarantinePanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.status = label("Opening the quarantine manifest…", "muted")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.grid = table(["Original path", "Status", "UTC timestamp", "Bytes"])
        layout.addWidget(self.grid, 1)
        controls = QHBoxLayout()
        self.restore = button("Restore selected", primary=True)
        self.restore_as = button("Restore with a different name")
        self.restore.setEnabled(False)
        self.restore_as.setEnabled(False)
        self.inspect = button("View manifest entry")
        for action in (self.restore, self.restore_as, self.inspect):
            controls.addWidget(action)
        controls.addStretch()
        layout.addLayout(controls)
        self.entries: list[dict] = []
        self.grid.itemSelectionChanged.connect(self.selection_changed)

    def selection_changed(self) -> None:
        item = self.selection()
        available = item is not None and item["state"] in ("Isolated", "Recovery required")
        self.restore.setEnabled(available)
        self.restore_as.setEnabled(available)

    def selection(self) -> dict | None:
        index = self.grid.currentRow()
        return self.entries[index] if 0 <= index < len(self.entries) else None
