import os
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication


def colors(theme: str) -> dict[str, str]:
    if theme == "Light":
        return {
            "base": "#ffffff",
            "side": "#f7f8fb",
            "panel": "#ffffff",
            "line": "#dce2ea",
            "text": "#121b2a",
            "muted": "#4f5d71",
            "accent": "#164f9e",
            "action": "#2255be",
            "action_hover": "#19499f",
            "action_pressed": "#153d89",
            "action_text": "#ffffff",
            "hover": "#edf1f7",
            "selected": "#e8f0ff",
            "focus": "#265fca",
            "red": "#9f3642",
            "bar": "#007f9c",
            "chart_fill": "#c6edf4",
            "violet": "#6348c0",
        }
    return {
        "base": "#08090b",
        "side": "#0d1014",
        "panel": "#101318",
        "line": "#28303a",
        "text": "#edf2f9",
        "muted": "#a6b3c4",
        "accent": "#a7c9ff",
        "action": "#345ec7",
        "action_hover": "#3d67cc",
        "action_pressed": "#2a50ab",
        "action_text": "#ffffff",
        "hover": "#1a2230",
        "selected": "#162a47",
        "focus": "#85b5ff",
        "red": "#ff9a9d",
        "bar": "#42c5e2",
        "chart_fill": "#173744",
        "violet": "#aa92ff",
    }


def apply_theme(app: QApplication, theme: str) -> None:
    if os.name == "nt" and not QFontDatabase.families():
        # Qt's Windows offscreen plugin may start with an unpopulated font database.
        directory = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("segoeui.ttf", "seguisb.ttf", "segoeuib.ttf", "seguisym.ttf"):
            QFontDatabase.addApplicationFont(str(directory / filename))
        if "Segoe UI" in QFontDatabase.families():
            app.setFont(QFont("Segoe UI"))
    c = colors(theme)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(c["base"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(c["panel"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(c["side"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(c["panel"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(c["selected"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(c["text"]))
    app.setPalette(palette)
    app.setStyleSheet(_stylesheet(c))


def _stylesheet(c: dict[str, str]) -> str:
    return f"""
        QWidget {{ color: {c["text"]}; font-size: 13px; }}
        QMainWindow, QWidget#workspace, QScrollArea {{ background: {c["base"]}; }}
        QScrollArea {{ border: none; }}
        QFrame#topBar {{ background: {c["side"]}; border-bottom: 1px solid {c["line"]}; }}
        QFrame#pageHeader {{ border-bottom: 1px solid {c["line"]}; }}
        QFrame[card="true"] {{
            background: {c["panel"]}; border: 1px solid {c["line"]}; border-radius: 8px;
        }}
        QLabel[kind="muted"] {{ color: {c["muted"]}; }}
        QLabel[kind="accent"] {{ color: {c["accent"]}; }}
        QLabel[kind="title"] {{ font-size: 26px; font-weight: 700; }}
        QLabel[kind="section"] {{ font-size: 15px; font-weight: 600; }}
        QLabel[kind="metric"] {{ font-size: 27px; font-weight: 600; }}
        QLabel[kind="brand"] {{ font-size: 17px; font-weight: 700; }}
        QLabel[kind="toast"] {{
            color: {c["text"]}; background: {c["selected"]}; border: 1px solid {c["focus"]};
            border-radius: 8px; padding: 10px 14px;
        }}
        QLabel[kind="emblem"] {{
            background: {c["action"]}; border-radius: 7px;
        }}
        QPushButton, QComboBox, QSpinBox, QLineEdit, QPlainTextEdit {{
            background: {c["panel"]}; border: 1px solid {c["line"]};
            border-radius: 5px; padding: 7px 12px;
        }}
        QPushButton {{ min-height: 20px; font-weight: 600; }}
        QPushButton:hover, QComboBox:hover {{ background: {c["hover"]}; }}
        QPushButton:pressed {{ background: {c["selected"]}; }}
        QPushButton:focus, QComboBox:focus, QLineEdit:focus, QSpinBox:focus,
        QPlainTextEdit:focus, QTableView:focus, QTreeView:focus, QCheckBox:focus {{
            border: 1px solid {c["focus"]};
        }}
        QPushButton:disabled {{ color: {c["muted"]}; background: {c["base"]}; }}
        QPushButton[primary="true"] {{
            background: {c["action"]}; color: {c["action_text"]}; border-color: {c["action"]};
        }}
        QPushButton[primary="true"]:hover {{ background: {c["action_hover"]}; }}
        QPushButton[primary="true"]:pressed {{ background: {c["action_pressed"]}; }}
        QPushButton[primary="true"]:focus {{ border-color: {c["accent"]}; }}
        QPushButton[primary="true"]:disabled {{
            background: {c["base"]}; color: {c["muted"]}; border-color: {c["line"]};
        }}
        QPushButton[nav="true"] {{
            background: transparent; border: 1px solid transparent;
            padding: 6px 8px; color: {c["muted"]}; font-weight: 600;
        }}
        QPushButton[nav="true"]:hover {{ background: {c["hover"]}; color: {c["text"]}; }}
        QPushButton[nav="true"]:checked {{
            background: {c["selected"]}; color: {c["accent"]};
        }}
        QPushButton[nav="true"]:focus {{ border: 1px solid {c["focus"]}; }}
        QCheckBox {{ border: 1px solid transparent; padding: 4px; spacing: 7px; }}
        QTableView, QTreeView {{
            background: {c["panel"]}; alternate-background-color: {c["side"]};
            border: 1px solid {c["line"]}; border-radius: 6px; gridline-color: {c["line"]};
            selection-background-color: {c["selected"]};
        }}
        QTableView::item, QTreeView::item {{ padding: 0 8px; }}
        QTreeView::item {{ min-height: 28px; }}
        QHeaderView::section {{
            background: {c["side"]}; color: {c["muted"]}; border: none;
            border-bottom: 1px solid {c["line"]}; padding: 8px; font-weight: 600;
        }}
        QProgressBar {{
            background: {c["side"]}; border: 1px solid {c["line"]};
            border-radius: 5px; text-align: center;
        }}
        QProgressBar::chunk {{ background: {c["bar"]}; border-radius: 4px; }}
        QToolTip {{ background: {c["panel"]}; color: {c["text"]}; border: 1px solid {c["line"]}; }}
        QStatusBar {{ background: {c["side"]}; color: {c["muted"]}; padding-left: 8px; }}
        QStatusBar::item {{ border: none; }}
        QTextBrowser {{
            background: {c["panel"]}; border: 1px solid {c["line"]}; border-radius: 9px;
            padding: 8px;
        }}
    """
