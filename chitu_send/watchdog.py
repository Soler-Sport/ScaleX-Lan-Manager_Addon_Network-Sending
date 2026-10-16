import datetime
import threading
import time
from PySide6.QtCore import QTimer

from . import logs


HANG_DUMP_AFTER_SEC = 8.0


_gui_heartbeat = [0.0]


def _start_hang_watchdog(dump_after=None):
    """Windows killed this process twice as "not responding" (AppHang,
    2026-09-30 and 2026-10-13 - the second one right after a picker window
    closed) with nothing in the log saying where. A GUI-thread timer stamps a
    heartbeat every second; a plain thread checks it and, if the GUI thread
    has been silent for HANG_DUMP_AFTER_SEC, writes every thread's Python
    stack into the log (faulthandler.dump_traceback, safe to call while the
    GUI thread is wedged) - once a minute while it stays wedged. Also turns
    on faulthandler for hard crashes. Returns the QTimer, which the caller
    must keep alive."""
    import faulthandler
    limit = HANG_DUMP_AFTER_SEC if dump_after is None else dump_after
    faulthandler.enable(file=logs._logf, all_threads=True)
    _gui_heartbeat[0] = time.monotonic()
    timer = QTimer()
    timer.setInterval(1000)
    timer.timeout.connect(lambda: _gui_heartbeat.__setitem__(0, time.monotonic()))
    timer.start()

    def watch():
        last_dump = 0.0
        while True:
            time.sleep(1.0)
            now = time.monotonic()
            age = now - _gui_heartbeat[0]
            if age > limit and now - last_dump > 60:
                last_dump = now
                logs._logf.write("[%s] === GUI THREAD NOT RESPONDING for %.0fs - thread stacks follow ===\r\n" % (
                    datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], age))
                logs._logf.flush()
                faulthandler.dump_traceback(file=logs._logf, all_threads=True)

    threading.Thread(target=watch, daemon=True, name="hang-watchdog").start()
    return timer
