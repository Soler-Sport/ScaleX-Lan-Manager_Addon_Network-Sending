import os
import tempfile

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPixmap


# ---------------------------------------------------------------------------
# Picker GUI - native Qt widgets (PySide6), styled via QSS below to match
# ScaleX's own "Базовый · Vorten" interface style (graphite & red, monospace,
# square corners). Printer/send progress goes straight from a worker thread to
# the GUI thread via Qt signals (thread-safe by construction).
#
# Values taken from ScaleX's own vorten.css (fetched 2026-10-16 from
# http://<scalex host>:<port>/vorten.css - fetch it again and diff against this
# block if ScaleX's theme ever changes):
#   --bg:#0b0b0c; --panel:#141415; --panel-2:#1c1c1e; --line:#2c2c2e;
#   --text:#ececec; --muted:#8e8e93; --accent:#ff4d4d; --accent-dark:#2a1010;
#   --vt-font: "Space Mono", "JetBrains Mono", ui-monospace, "Cascadia Mono", Consolas, monospace;
#   input,select,textarea { background:#0b0b0c; border-color:var(--line); }
#   .primary { background:var(--accent); color:#140a0a; }  .primary:disabled { background:#26262a; color:var(--muted); }
#   .notice { border-left-color:var(--accent); background:var(--accent-dark); color:#ffb0b0; }
#   .bulk-printer-option { background:#141415; border-color:var(--line); }
#   .bulk-printer-option:has(:checked) { border-color:rgba(255,77,77,.65); background:rgba(255,77,77,.06); }
#   * { border-radius: 0 !important }   <- square geometry is part of the style
# --green/--red (state colours) are not overridden by Vorten and stay as in
# styles.css :root: #73d49a / #ff7e78.
# ---------------------------------------------------------------------------
COLOR_BG = "#0b0b0c"
COLOR_PANEL = "#141415"
COLOR_PANEL_2 = "#1c1c1e"
COLOR_LINE = "#2c2c2e"
COLOR_TEXT = "#ececec"
COLOR_TEXT_DIM = "#8e8e93"
COLOR_ACCENT = "#ff4d4d"
COLOR_ACCENT_TEXT = "#140a0a"   # text painted ON TOP of an accent-colored surface (.primary)
COLOR_ACCENT_DARK = "#2a1010"   # notice background
COLOR_ACCENT_SOFT = "#ffb0b0"   # notice text
COLOR_DISABLED_BG = "#26262a"
COLOR_GREEN = "#73d49a"         # "ready"/"prepared" state
COLOR_RED = "#ff7e78"           # errors / "busy"
COLOR_CARD_BG = "#141415"       # printer cards
COLOR_INPUT_BG = "#0b0b0c"      # text inputs
# Same fallback chain as ScaleX's --vt-font; the first installed family wins.
FONT_FAMILIES = ["Space Mono", "JetBrains Mono", "Cascadia Mono", "Consolas"]


def app_font(point_size=9):
    """The application-wide font: Vorten's monospace chain (QSS can't express a
    fallback list, so it is set on the QApplication instead)."""
    font = QFont()
    font.setFamilies(FONT_FAMILIES)
    font.setPointSize(point_size)
    return font


def _check_icon_path():
    """QSS can't draw a check mark by itself - render one into a small PNG (dark on the
    accent-filled indicator) and point the stylesheet at it."""
    path = os.path.join(tempfile.gettempdir(), "slm_chitu_send_check.png")
    pm = QPixmap(14, 14)
    pm.fill(Qt.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(COLOR_ACCENT_TEXT))
    pen.setWidthF(2.0)
    pen.setCapStyle(Qt.SquareCap)
    pen.setJoinStyle(Qt.MiterJoin)
    painter.setPen(pen)
    painter.drawPolyline([QPoint(3, 7), QPoint(6, 10), QPoint(11, 4)])
    painter.end()
    pm.save(path)
    return path


PICKER_QSS = """
QMainWindow, #pickerCentral, #pickerScrollContents { background: %(bg)s; }
QLabel { color: %(text)s; }
#eyebrowLabel { color: %(accent)s; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
#headingLabel { color: %(text)s; font-size: 17px; font-weight: 700; }
#fieldLabel { color: %(dim)s; font-size: 11.5px; }
#machineNotice { background: %(accentdark)s; color: %(accentsoft)s; border-left: 3px solid %(accent)s;
    border-radius: 0; padding: 8px 10px; }
#selectedCountLabel { color: %(dim)s; font-size: 11.5px; }
QLineEdit { background: %(inputbg)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 0; padding: 8px 10px; selection-background-color: %(accent)s; selection-color: %(accenttext)s; }
QLineEdit:focus { border: 1px solid %(accent)s; }
QLineEdit:disabled { color: %(dim)s; }
QComboBox { background: %(inputbg)s; color: %(text)s; border: 1px solid %(line)s; border-radius: 0; padding: 6px 8px; }
QComboBox:focus, QComboBox:on { border: 1px solid %(accent)s; }
QComboBox QAbstractItemView { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s; border-radius: 0;
    selection-background-color: %(accentdark)s; selection-color: %(accentsoft)s; outline: none; }
QCheckBox { color: %(text)s; spacing: 8px; }
QCheckBox:disabled { color: %(dim)s; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid %(dim)s; background: %(inputbg)s; border-radius: 0; }
QCheckBox::indicator:hover { border: 1px solid %(accent)s; }
QCheckBox::indicator:checked { background: %(accent)s; border: 1px solid %(accent)s; }
QCheckBox::indicator:disabled { border: 1px solid %(line)s; background: %(inputbg)s; }
QCheckBox::indicator:checked:disabled { background: rgba(255, 77, 77, .42); border: 1px solid rgba(255, 77, 77, .42); }
QPushButton { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 0; padding: 9px 15px; }
QPushButton:hover { border: 1px solid %(accent)s; }
QPushButton:disabled { color: %(dim)s; }
#sendBtn { background: %(accent)s; color: %(accenttext)s; font-weight: 700; border: 1px solid %(accent)s; }
#sendBtn:hover { background: #ff6a6a; border: 1px solid #ff6a6a; }
#sendBtn:disabled { background: %(disabledbg)s; color: %(dim)s; border: 1px solid %(line)s; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: %(bg)s; width: 10px; margin: 0; border: none; }
QScrollBar::handle:vertical { background: %(line)s; min-height: 28px; border-radius: 0; }
QScrollBar::handle:vertical:hover { background: %(accent)s; }
QScrollBar:horizontal { background: %(bg)s; height: 10px; margin: 0; border: none; }
QScrollBar::handle:horizontal { background: %(line)s; min-width: 28px; border-radius: 0; }
QScrollBar::handle:horizontal:hover { background: %(accent)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QToolTip { background: %(panel2)s; color: %(text)s; border: 1px solid %(line)s; padding: 4px 6px; }
QMenu { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s; padding: 4px 0; }
QMenu::item { padding: 6px 24px; background: transparent; }
QMenu::item:selected { background: %(accentdark)s; color: %(accentsoft)s; }
QMenu::separator { height: 1px; background: %(line)s; margin: 4px 0; }
#printerRow { background: %(cardbg)s; border: 1px solid %(line)s; border-radius: 0; }
#printerRow[selected="true"] { border: 1px solid rgba(255, 77, 77, .65); background: rgba(255, 77, 77, .06); }
#printerName { color: %(text)s; font-size: 12.5px; font-weight: 700; }
#printerMeta { color: %(dim)s; font-size: 11.5px; }
#memoryFitLabel { font-size: 11px; margin-top: 1px; }
#memoryFitLabel[fit="yes"] { color: %(green)s; }
#memoryFitLabel[fit="no"] { color: %(red)s; font-weight: 600; }
#stateLabel[state="ready"] { color: %(green)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="busy"] { color: %(red)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="offline"] { color: %(dim)s; font-size: 11px; font-weight: 600; }
#recSummary { color: %(dim)s; font-size: 11px; }
#miniProgressLabel { color: %(dim)s; font-size: 11px; }
#retryBtn { background: transparent; color: %(red)s; border: 1px solid %(red)s;
    border-radius: 0; padding: 2px 9px; font-size: 10.5px; font-weight: 600; }
#retryBtn:hover { background: rgba(255, 126, 120, .12); }
QTabWidget::pane { border: none; background: %(bg)s; }
QTabWidget { background: %(bg)s; }
QTabBar { background: %(bg)s; border: none; }
QTabBar::tab { background: %(panel)s; color: %(dim)s; border: 1px solid %(line)s; border-bottom: none;
    border-radius: 0; padding: 7px 28px 7px 12px; margin-right: 2px; max-width: 210px; }
QTabBar::tab:selected { background: %(panel2)s; color: %(text)s; border: 1px solid %(line)s; border-top: 2px solid %(accent)s; }
#tabClose { background: transparent; border: none; border-radius: 0; color: %(dim)s; font-size: 11px; padding: 2px 5px; }
#tabClose:hover { background: rgba(255, 77, 77, .2); color: %(accent)s; }
QTabBar::tab:hover { color: %(text)s; }
QProgressBar { background: %(panel2)s; border: 1px solid %(line)s; border-radius: 0;
    max-height: 8px; min-height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: %(accent)s; border-radius: 0; }
""" % {
    "bg": COLOR_BG, "panel": COLOR_PANEL, "panel2": COLOR_PANEL_2, "line": COLOR_LINE,
    "text": COLOR_TEXT, "dim": COLOR_TEXT_DIM, "accent": COLOR_ACCENT,
    "accenttext": COLOR_ACCENT_TEXT, "accentdark": COLOR_ACCENT_DARK, "accentsoft": COLOR_ACCENT_SOFT,
    "disabledbg": COLOR_DISABLED_BG, "green": COLOR_GREEN, "red": COLOR_RED,
    "cardbg": COLOR_CARD_BG, "inputbg": COLOR_INPUT_BG,
}


def apply_theme(app):
    """Application-wide look: Vorten font chain, stylesheet, and the check-mark image."""
    app.setFont(app_font())
    qss = PICKER_QSS
    try:
        icon = _check_icon_path().replace("\\", "/")
        qss += 'QCheckBox::indicator:checked { image: url("%s"); }' % icon
    except Exception:
        pass  # no check mark image is cosmetic - the filled indicator still shows the state
    app.setStyleSheet(qss)
