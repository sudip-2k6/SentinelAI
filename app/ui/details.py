import html
import tempfile
from pathlib import Path

from PySide6.QtGui import QPdfWriter, QTextDocument, QTextOption
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.ui.widgets import ScoreGauge, button


def _e(value: object) -> str:
    # Escape markup and display every untrusted value as text.
    return html.escape(str(value), quote=True)


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return "<p>None recorded.</p>"
    headings = "".join(f"<th>{_e(header)}</th>" for header in headers)
    items = "".join(
        "<tr>" + "".join(f"<td>{_e(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table border='1' cellspacing='0' cellpadding='5'><tr>{headings}</tr>{items}</table>"


def report_markup(data: dict) -> str:
    analysis = data.get("analysis") or {}
    model = data.get("assessment") or {}
    score = model.get("probability")
    threshold = model.get("threshold")
    anomaly = model.get("anomaly_percentile")
    basics = [
        [title, value]
        for title, value in (
            ("Path", data.get("path")),
            ("Timestamp (UTC)", data.get("timestamp")),
            ("SHA-256", data.get("sha256")),
            ("Size (bytes)", data.get("size")),
            ("Format", data.get("format")),
            ("Status", data.get("status")),
            ("Filesystem executable bits", data.get("executable")),
            ("File entropy (bits/byte)", analysis.get("entropy")),
            ("Message", data.get("message")),
        )
        if value is not None and value != ""
    ]
    assessment = [
        [title, value]
        for title, value in (
            ("Status", model.get("status")),
            ("Review priority", model.get("review")),
            ("Model version", model.get("model_version")),
            ("Explanation", model.get("reason")),
            ("Calibrated score", f"{score:.2%}" if score is not None else None),
            ("Classifier threshold", f"{threshold:.2%}" if threshold is not None else None),
            ("Experimental anomaly percentile", f"{anomaly:.2%}" if anomaly is not None else None),
            ("TreeSHAP baseline (raw log-odds)", model.get("baseline")),
        )
        if value is not None and value != ""
    ]
    sections = [
        [s["name"], s["size"], f"{s['entropy']:.3f}", s["executable"], s["writable"]]
        for s in analysis.get("sections", [])
    ]
    evidence = [
        [
            row["feature"],
            f"{row['value']:.5g}",
            f"{row['contribution']:+.5g}",
            "Raises raw score" if row["contribution"] > 0 else "Lowers raw score",
        ]
        for row in model.get("evidence", [])
    ]
    imports = [[item] for item in analysis.get("imports", [])]
    output = (
        "<!doctype html><html><head><meta charset='utf-8'><title>SentinelAI scan report</title>"
        "<style>h1,h2 {font-weight:600} td,th {overflow-wrap:anywhere} </style>"
        "</head><body><h1>SentinelAI scan report</h1>"
        "<h2>File and scan</h2>"
        + _table(["Field", "Value"], basics)
        + "<h2>Model assessment</h2>"
        + _table(["Field", "Value"], assessment)
    )
    if score is not None:
        output += (
            "<p>Scores and contributions express model evidence. They do not establish "
            "that the file ran or behaved maliciously. TreeSHAP contributions are in raw "
            "log-odds before probability calibration.</p>"
            + _table(["Feature", "Value", "Contribution", "Direction"], evidence)
        )
    if analysis:
        output += (
            "<h2>Executable headers</h2>"
            + _table(["Field", "Value"], [[k, v] for k, v in analysis["headers"].items()])
            + "<h2>Sections</h2>"
            + _table(["Name", "Bytes", "Entropy", "Execute", "Write"], sections)
            + "<h2>Imports and dependencies</h2>"
            + _table(["Name"], imports)
            + "<h2>String markers</h2><p>Counts cover the first 4 MiB. Legitimate files can "
            "contain these markers.</p>"
            + _table(["Marker", "Count"], [[k, v] for k, v in analysis["indicators"].items()])
        )
    return output + "</body></html>"


def write_report(destination: Path, markup: str, kind: str) -> None:
    with tempfile.TemporaryDirectory(prefix=".sentinel-report-", dir=destination.parent) as folder:
        output = Path(folder) / destination.name
        if kind == "HTML":
            output.write_text(markup, encoding="utf-8")
        elif kind == "PDF":
            document = QTextDocument()
            document.setDefaultStyleSheet("body { color: #182333; background: white; }")
            text_options = document.defaultTextOption()
            text_options.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
            document.setDefaultTextOption(text_options)
            document.setHtml(markup)
            writer = QPdfWriter(str(output))
            writer.setCreator("SentinelAI")
            writer.setTitle("SentinelAI scan report")
            writer.setResolution(120)
            document.print_(writer)
            del writer
            if not output.is_file():
                raise OSError("The PDF output could not be written.")
            with output.open("rb") as stream:
                if stream.read(5) != b"%PDF-":
                    raise OSError("The PDF output is invalid.")
        else:
            raise ValueError("Unsupported report format.")
        output.replace(destination)


class Details(QDialog):
    def __init__(self, data: dict, theme: str, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scan details")
        self.resize(820, 690)
        self.markup = report_markup(data)
        view = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        toolbar.addWidget(ScoreGauge(theme, (data.get("assessment") or {}).get("probability")))
        toolbar.addWidget(QLabel("Calibrated\nmodel score"))
        toolbar.addStretch()
        for kind in ("HTML", "PDF"):
            export = button(f"Export {kind}")
            export.clicked.connect(lambda _checked=False, kind=kind: self.export(kind))
            toolbar.addWidget(export)
        view.addLayout(toolbar)
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        self.browser.setHtml(self.markup)
        view.addWidget(self.browser)

    def export(self, kind: str) -> None:
        filename, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {kind}",
            f"sentinel-scan.{kind.lower()}",
            f"{kind} files (*.{kind.lower()})",
        )
        if not filename:
            return
        try:
            write_report(Path(filename), self.markup, kind)
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", html.escape(str(exc)))
