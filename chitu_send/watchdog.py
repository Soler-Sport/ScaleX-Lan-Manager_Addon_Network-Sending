import time
from PySide6.QtCore import QTimer

from . import logs


HANG_DUMP_AFTER_SEC = 8.0


_gui_heartbeat = [0.0]


def _start_hang_watchdog(dump_after=None):
    """Windows killed this process as "not responding" (AppHang: 2026-09-30, 2026-10-13 and
    2026-10-19 12:21) with nothing in the log saying where - the Python-thread watchdog this
    replaced never wrote a line either, because a main thread stuck in a native call that
    keeps the GIL starves every Python thread, the watchdog included. This uses
    faulthandler.dump_traceback_later instead: a C-level timer (no GIL needed) that prints
    every thread's Python stack into the log if the GUI thread has not re-armed it for
    HANG_DUMP_AFTER_SEC. A GUI-thread timer re-arms it every second, so it only ever fires
    while the GUI thread is wedged. Also turns on faulthandler for hard crashes. Returns the
    QTimer, which the caller must keep alive."""
    import faulthandler
    limit = HANG_DUMP_AFTER_SEC if dump_after is None else dump_after
    faulthandler.enable(file=logs._logf, all_threads=True)

    def beat():
        _gui_heartbeat[0] = time.monotonic()
        faulthandler.dump_traceback_later(limit, repeat=False, file=logs._logf, exit=False)

    beat()
    timer = QTimer()
    timer.setInterval(1000)
    timer.timeout.connect(beat)
    timer.start()
    return timer
