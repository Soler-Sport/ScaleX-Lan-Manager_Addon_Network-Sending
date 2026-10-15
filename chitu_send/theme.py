


# ---------------------------------------------------------------------------
# Picker GUI - native Qt widgets (PySide6), styled via QSS below to look like
# a dashboard panel instead of a generic OS dialog. Replaces the old
# pywebview + local-HTTP-server + PAGE_HTML approach entirely: no browser
# engine, no HTTP server, no polling - printer/send progress goes straight
# from a worker thread to the GUI thread via Qt signals (thread-safe by
# construction: Qt auto-queues delivery when emitter and receiver live on
# different threads, no PostMessage/AttachThreadInput-style plumbing needed
# the way the old WebView2-based attempts required).
#
# Real values, copied byte-for-byte from ScaleX's own styles.css :root
# block and its actual rules for the specific pieces this window mirrors
# (2026-08-21, http://<scalex host>:<port>/styles.css - fetch it again and
# diff against this block if ScaleX's theme ever changes):
#   :root { --bg:#111315; --panel:#1a1d20; --panel-2:#22262a; --line:#31363b;
#            --text:#f4f1ea; --muted:#999f9f; --accent:#e8ff65;
#            --green:#73d49a; --red:#ff7e78; }
#   input,select,textarea { background:#111416; border:1px solid var(--line); border-radius:8px; }
#   .bulk-printer-option { background:#15181a; border-radius:9px; }  <- printer cards specifically, NOT --panel
#   .bulk-printer-option:has(:checked) { border-color: rgba(232,255,101,.65); background: rgba(232,255,101,.06); }
#   .bulk-printer-state.is-ready { color: var(--green); }   <- NOT --accent, ScaleX uses green for "ready"
#   .bulk-printer-state.is-error { color: var(--red); }
#   .operator-prepared-toggle.active { color: var(--green); border-color: rgba(115,212,154,.7); background: rgba(115,212,154,.12); }
#   .primary { background: var(--accent); color: #12140c; font-weight:700; border-radius:9px; padding:10px 15px; }
#   .primary:disabled { background:#25292c; color: var(--muted); }
#   button { border:1px solid var(--line); border-radius:9px; padding:10px 15px; background: var(--panel); }
#   font-family: "Segoe UI", Arial, sans-serif;
# Every color the picker uses funnels through these constants and
# PICKER_QSS below - re-derive from the real stylesheet, don't hand-tune
# hex values here directly.
# ---------------------------------------------------------------------------
COLOR_BG = "#111315"


COLOR_PANEL = "#1a1d20"


COLOR_PANEL_2 = "#22262a"


COLOR_LINE = "#31363b"


COLOR_TEXT = "#f4f1ea"


COLOR_TEXT_DIM = "#999f9f"


COLOR_ACCENT = "#e8ff65"


COLOR_ACCENT_TEXT = "#12140c"  # text painted ON TOP of an accent-colored surface (.primary)


COLOR_GREEN = "#73d49a"        # "ready"/"prepared" state - ScaleX does NOT reuse accent for this


COLOR_RED = "#ff7e78"


COLOR_CARD_BG = "#15181a"      # printer cards specifically - distinct from --panel, not a typo


COLOR_INPUT_BG = "#111416"     # text inputs specifically - distinct from --panel, not a typo


FONT_FAMILY = "Segoe UI"


PICKER_QSS = """
* { font-family: "%(font)s"; }
QMainWindow, #pickerCentral, #pickerScrollContents { background: %(bg)s; }
QLabel { color: %(text)s; }
#eyebrowLabel { color: %(accent)s; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
#headingLabel { color: %(text)s; font-size: 17px; font-weight: 700; }
#fieldLabel { color: %(dim)s; font-size: 11.5px; }
#machineNotice { background: %(panel2)s; color: %(accent)s; border-left: 3px solid %(accent)s;
    border-radius: 4px; padding: 8px 10px; }
#selectedCountLabel { color: %(dim)s; font-size: 11.5px; }
QLineEdit { background: %(inputbg)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 8px; padding: 8px 10px; }
QLineEdit:focus { border: 1px solid %(accent)s; }
QLineEdit:disabled { color: %(dim)s; }
QCheckBox { color: %(text)s; spacing: 6px; }
QCheckBox:disabled { color: %(dim)s; }
QPushButton { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 9px; padding: 9px 15px; }
QPushButton:hover { border: 1px solid %(accent)s; }
QPushButton:disabled { color: %(dim)s; }
#sendBtn { background: %(accent)s; color: %(accenttext)s; font-weight: 700; border: none; }
#sendBtn:disabled { background: #25292c; color: %(dim)s; }
QScrollArea { border: none; background: transparent; }
#printerRow { background: %(cardbg)s; border: 1px solid %(line)s; border-radius: 9px; }
#printerRow[selected="true"] { border: 1px solid rgba(232, 255, 101, .65); background: rgba(232, 255, 101, .06); }
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
    border-radius: 6px; padding: 2px 9px; font-size: 10.5px; font-weight: 600; }
#retryBtn:hover { background: rgba(255, 126, 120, .12); }
QTabWidget::pane { border: none; }
QTabBar::tab { background: %(panel2)s; color: %(dim)s; border: 1px solid %(line)s; border-bottom: none;
    border-top-left-radius: 8px; border-top-right-radius: 8px; padding: 7px 12px; margin-right: 2px; max-width: 210px; }
QTabBar::tab:selected { background: %(panel)s; color: %(text)s; border-color: rgba(232, 255, 101, .65); }
QTabBar::tab:hover { color: %(text)s; }
QProgressBar { background: %(panel2)s; border: 1px solid %(line)s; border-radius: 5px;
    max-height: 8px; min-height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: %(accent)s; border-radius: 5px; }
""" % {
    "bg": COLOR_BG, "panel": COLOR_PANEL, "panel2": COLOR_PANEL_2, "line": COLOR_LINE,
    "text": COLOR_TEXT, "dim": COLOR_TEXT_DIM, "accent": COLOR_ACCENT,
    "accenttext": COLOR_ACCENT_TEXT, "green": COLOR_GREEN, "red": COLOR_RED,
    "cardbg": COLOR_CARD_BG, "inputbg": COLOR_INPUT_BG, "font": FONT_FAMILY,
}
