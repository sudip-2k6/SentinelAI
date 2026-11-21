import html
from datetime import UTC, datetime, timedelta

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import colors

_ICONS = {
    "shield": (
        ((12, 2), (21, 6), (20, 14), (17, 19), (12, 22), (7, 19), (4, 14), (3, 6), (12, 2)),
        ((8, 12), (11, 15), (16, 9)),
    ),
    "file": (
        ((13, 3), (5, 3), (5, 21), (19, 21), (19, 9), (13, 3), (13, 9), (19, 9)),
        ((8, 13), (16, 13)),
        ((8, 17), (13, 17)),
    ),
    "activity": (((2, 12), (6, 12), (9, 5), (13, 19), (16, 12), (22, 12)),),
    "history": (
        ((4, 3), (20, 3), (20, 21), (4, 21), (4, 3)),
        ((8, 8), (16, 8)),
        ((8, 12), (16, 12)),
        ((8, 16), (13, 16)),
    ),
}


def icon(name: str, color: str, size: int) -> QPixmap:
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(size / 24, size / 24)
    pen = QPen(QColor(color), 1.65)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    for points in _ICONS[name]:
        painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))
    painter.end()
    return pixmap


def label(text: str, kind: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setProperty("kind", kind)
    return widget


def button(text: str, *, primary: bool = False) -> QPushButton:
    widget = QPushButton(text)
    widget.setProperty("primary", primary)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


def card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(8)
    return frame, layout


def empty_state(title: str, description: str) -> QFrame:
    frame, layout = card()
    layout.addStretch()
    layout.addWidget(label(title, "section"), alignment=Qt.AlignmentFlag.AlignHCenter)
    help_text = label(description, "muted")
    help_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
    help_text.setWordWrap(True)
    layout.addWidget(help_text)
    layout.addStretch()
    return frame


def table(headings: list[str], stretch: int = 0) -> QTableWidget:
    widget = QTableWidget(0, len(headings))
    widget.setHorizontalHeaderLabels(headings)
    widget.setAlternatingRowColors(True)
    widget.setShowGrid(False)
    widget.verticalHeader().hide()
    widget.verticalHeader().setDefaultSectionSize(33)
    widget.setWordWrap(False)
    widget.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    header = widget.horizontalHeader()
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    return widget


def rows(widget: QTableWidget, values: list[tuple[object, ...]]) -> None:
    widget.setUpdatesEnabled(False)
    widget.setRowCount(len(values))
    for index, row in enumerate(values):
        for column, value in enumerate(row):
            cell = QTableWidgetItem(str(value) if value is not None else "—")
            if value is not None:
                cell.setToolTip(f"<qt>{html.escape(str(value))}</qt>")
            widget.setItem(index, column, cell)
    widget.setUpdatesEnabled(True)


class ActivityChart(QWidget):
    def __init__(self, theme: str) -> None:
        super().__init__()
        self.theme = theme
        self.counts: list[tuple[str, int]] = []
        self.columns: list[QRectF] = []
        self.setMinimumHeight(114)
        self.setMouseTracking(True)
        self.setAccessibleName("Scan counts for the past seven days")

    def set_counts(self, data: list[dict]) -> None:
        counts = {row["day"]: row["scans"] for row in data}
        today = datetime.now(UTC).date()
        dates = [today - timedelta(days=days) for days in range(6, -1, -1)]
        self.counts = [(day.isoformat(), counts.get(day.isoformat(), 0)) for day in dates]
        self.setAccessibleDescription(", ".join(f"{name}: {count}" for name, count in self.counts))
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        if not self.counts:
            return
        c = colors(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bottom = self.height() - 24
        peak = max(2, *(count for _, count in self.counts))
        peak += peak % 2
        axis = painter.fontMetrics().horizontalAdvance(f"{peak:,}") + 14
        step = (self.width() - axis) / 7
        for ratio in (0.0, 0.5, 1.0):
            y = bottom - ratio * (bottom - 8)
            painter.setPen(QPen(QColor(c["line"])))
            painter.drawLine(QPointF(axis, y), QPointF(self.width() - 1, y))
            painter.setPen(QColor(c["muted"]))
            painter.drawText(
                QRectF(0, y - 9, axis - 8, 18),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{int(peak * ratio):,}",
            )
        self.columns = []
        points = []
        for index, (name, count) in enumerate(self.counts):
            x = axis + step * index
            points.append(QPointF(x + step / 2, bottom - (bottom - 8) * count / peak))
            self.columns.append(QRectF(x, 0, step, bottom))
            painter.setPen(QColor(c["muted"]))
            painter.drawText(
                QRectF(x, bottom + 3, step, 21),
                Qt.AlignmentFlag.AlignCenter,
                name[5:],
            )
        fill = QLinearGradient(0, 8, 0, bottom)
        fill.setColorAt(0, QColor(c["chart_fill"]))
        fill.setColorAt(1, QColor(c["panel"]))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill)
        painter.drawPolygon(
            QPolygonF([QPointF(points[0].x(), bottom), *points, QPointF(points[-1].x(), bottom)])
        )
        painter.setPen(QPen(QColor(c["bar"]), 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolyline(QPolygonF(points))
        painter.setBrush(QColor(c["panel"]))
        for point in points:
            painter.drawEllipse(point, 3, 3)
        painter.end()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        for index, column in enumerate(self.columns):
            if column.contains(event.position()):
                day, count = self.counts[index]
                QToolTip.showText(event.globalPosition().toPoint(), f"{day} · {count} scans", self)
                return
        QToolTip.hideText()


class ScoreGauge(QWidget):
    def __init__(self, theme: str, score: float | None, *, color: str = "bar") -> None:
        super().__init__()
        self.theme = theme
        self.color = color
        self.setFixedSize(92, 92)
        self.setAccessibleName("Calibrated model score")
        self.set_score(score)

    def set_score(self, score: float | None) -> None:
        self.score = score
        self.setAccessibleDescription("Unavailable" if score is None else f"{score:.1%}")
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:
        c = colors(self.theme)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        box = QRectF(8, 8, 76, 76)
        painter.setPen(QPen(QColor(c["line"]), 7))
        painter.drawEllipse(box)
        if self.score is not None:
            painter.setPen(QPen(QColor(c[self.color]), 7))
            painter.drawArc(box, 90 * 16, -round(360 * 16 * self.score))
        painter.setPen(QColor(c["text"]))
        font = painter.font()
        font.setPixelSize(20)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(
            box, Qt.AlignmentFlag.AlignCenter, "—" if self.score is None else f"{self.score:.0%}"
        )
        painter.end()
