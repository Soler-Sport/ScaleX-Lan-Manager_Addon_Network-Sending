import os
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap
from PySide6.QtWidgets import QFileDialog, QMenu, QSystemTrayIcon

from . import config
from .logs import logmsg
from .picker import open_picker_window
from .theme import COLOR_ACCENT


def show_waiting_notice(tray, slice_label):
    tray.showMessage(
        "slm_chitu_send",
        "Жду файл от CHITUBOX: %s\nБольшие файлы сохраняются до минуты - окно откроется само." % slice_label,
        QSystemTrayIcon.Information, 8000)


# "1a / Send over grid" from the project's icon design pass (2026-08-21) -
# a multi-resolution .ico (16/24/32/48/256, see slm_chitu_send_icon.ico) so
# Windows can pick a crisp size for the tray, Alt-Tab, and taskbar instead
# of scaling one flat bitmap.
ICON_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "slm_chitu_send_icon.ico")


def _make_tray_icon():
    if os.path.isfile(ICON_PATH):
        icon = QIcon(ICON_PATH)
        if not icon.isNull():
            return icon
        logmsg("=== _make_tray_icon: QIcon(%r) loaded but is null, falling back to drawn dot ===", ICON_PATH)
    else:
        logmsg("=== _make_tray_icon: %r not found, falling back to drawn dot ===", ICON_PATH)
    # Fallback so a missing/corrupt icon file never stops the app from
    # starting - just a plain accent-colored dot, same as before this icon
    # existed.
    pm = QPixmap(32, 32)
    pm.fill(Qt.transparent)
    from PySide6.QtGui import QPainter, QBrush
    painter = QPainter(pm)
    painter.setBrush(QBrush(QColor(COLOR_ACCENT)))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(2, 2, 28, 28)
    painter.end()
    return QIcon(pm)


def _manual_send_dialog():
    path, _ = QFileDialog.getOpenFileName(
        None, "Выбрать файл для отправки", "",
        "Слайс-файлы (*.ctb *.goo *.cbddlp *.pwmx);;Все файлы (*)")
    if path:
        open_picker_window(path)


def build_tray_icon(app):
    tray = QSystemTrayIcon(_make_tray_icon())
    tray.setToolTip("slm_chitu_send - CHITUBOX -> ScaleX bridge")
    menu = QMenu()
    act_manual = QAction("Отправить файл вручную…")
    act_manual.triggered.connect(_manual_send_dialog)
    act_log = QAction("Открыть лог")
    act_log.triggered.connect(lambda: os.startfile(config.LOG_PATH))
    act_quit = QAction("Выход")
    act_quit.triggered.connect(app.quit)
    menu.addAction(act_manual)
    menu.addAction(act_log)
    menu.addSeparator()
    menu.addAction(act_quit)
    tray.setContextMenu(menu)
    tray.activated.connect(
        lambda reason: _manual_send_dialog() if reason == QSystemTrayIcon.DoubleClick else None)
    tray.show()
    return tray, menu, (act_manual, act_log, act_quit)  # keep refs alive - PySide6 doesn't on its own
