import ctypes
import os
import socket
import sys
import threading
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from . import app_controller
from . import config
from . import logs
from .app_controller import AppController
from .cleanup import _received_dir_cleanup_loop
from .hook_injector import chitubox_hook_injector_loop
from .logs import logmsg
from .picker import open_picker_window
from .protocol import _chitubox_accept_loop
from .shm import SHM_NAME, create_shared_memory
from .theme import PICKER_QSS
from .tray import _make_tray_icon, build_tray_icon, show_waiting_notice
from .watchdog import _start_hang_watchdog
from .watchers import _pending_dir_watcher, slicer_file_watcher


def main():
    logmsg("=== slm_chitu_send started PID=%d ===", os.getpid())
    logmsg("=== ScaleX: http://%s:%d ===", config.SCALEX_HOST, config.SCALEX_PORT)

    # Without this, Windows' taskbar groups every pythonw.exe-hosted window
    # under Python's own generic app identity, and the taskbar BUTTON
    # specifically (unlike the title bar/Alt-Tab icon, which honors Qt's
    # WM_SETICON fine either way) falls back to pythonw.exe's own default
    # icon instead of the one set below via app.setWindowIcon() - confirmed
    # live 2026-08-21 (tray icon correct, picker window's taskbar button
    # still default). Giving the process its own AppUserModelID, before any
    # window exists, is the standard fix - decouples it from the shared
    # "Python" taskbar identity entirely. Must be set before QApplication()
    # creates the first window.
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SolerSport.SlmChituSend.NetworkSending")
    except Exception as e:
        logmsg("=== SetCurrentProcessExplicitAppUserModelID FAILED (taskbar icon may show default): %s ===", e)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # tray-resident: closing every picker window must not exit the app
    app.setStyleSheet(PICKER_QSS)
    app.setWindowIcon(_make_tray_icon())  # every PickerWindow inherits this (taskbar/Alt-Tab), not just the tray

    app_controller.controller = AppController()
    app_controller.controller.file_captured.connect(open_picker_window, Qt.QueuedConnection)

    tray, tray_menu, tray_actions = build_tray_icon(app)  # noqa: F841 - refs kept alive deliberately
    hang_timer = _start_hang_watchdog()  # noqa: F841 - ref kept alive deliberately
    app_controller.controller.save_requested.connect(lambda label: show_waiting_notice(tray, label), Qt.QueuedConnection)

    threading.Thread(target=slicer_file_watcher, daemon=True).start()
    threading.Thread(target=_pending_dir_watcher, daemon=True).start()
    threading.Thread(target=_received_dir_cleanup_loop, daemon=True).start()
    threading.Thread(target=chitubox_hook_injector_loop, daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", 0))
    port = listen_sock.getsockname()[1]
    logmsg("=== CHITUBOX protocol listening on 127.0.0.1:%d ===", port)
    listen_sock.listen(5)

    ok = create_shared_memory(SHM_NAME, str(port))
    logmsg("=== shared memory created=%s ===", "yes" if ok else "NO")
    if not ok:
        QMessageBox.critical(None, "slm_chitu_send", "Не удалось создать сегмент разделяемой памяти (см. лог). Выход.")
        return 1

    # CHITUBOX only ever opens one persistent connection - handling it in a
    # background thread frees up the main thread for Qt's event loop
    # (app.exec() below blocks here for the process lifetime).
    threading.Thread(target=_chitubox_accept_loop, args=(listen_sock,), daemon=True).start()

    print("slm_chitu_send running (Qt). Log: %s" % config.LOG_PATH)
    print("Picker windows open automatically on each capture; tray icon has manual send / log / exit.")

    try:
        ret = app.exec()
    finally:
        logmsg("=== slm_chitu_send exiting ===")
        logs._logf.close()
    return ret
