import ctypes
from ctypes import wintypes

from .logs import logmsg
from .winapi import user32


SPI_GETFOREGROUNDLOCKTIMEOUT = 0x2000


SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001


SPIF_SENDCHANGE = 0x2


VK_MENU = 0x12          # Alt


KEYEVENTF_KEYUP = 0x0002


def force_window_to_foreground(qwidget):
    """A native Qt window created (indirectly, via a queued signal - see
    AppController below) while some other app is in the foreground - e.g.
    CHITUBOX, right after the "Отправка по сети" click - doesn't reliably
    grab focus on its own either; same underlying Windows restriction that
    made the old pywebview version need a trick here too. Does NOT use
    AttachThreadInput (an earlier version of this trick did, for the
    pywebview build - see git history/PR #1 - it ties this thread's input
    queue to whatever process currently owns the foreground, and can freeze
    both windows if that process is even briefly busy at that exact
    moment).

    Zeroing the system-wide foreground-lock timeout alone (the only trick
    this used to do) turned out NOT to be enough on its own - confirmed
    live 2026-08-21: the log showed "SetForegroundWindow declined" on every
    single call, and the user reported the picker always just sits in the
    taskbar needing a manual click. The lock-timeout value only controls
    how long Windows waits before giving up and flashing the taskbar
    button instead of switching - modern Windows (10/11) separately checks
    whether the calling process looks like it just received real user
    input before honoring SetForegroundWindow from a background process at
    all, and slm_chitu_send (reacting to a background thread's signal) never
    does. The standard, widely-documented workaround for that second check:
    synthesize a harmless Alt keydown/keyup via keybd_event right before
    asking - this only feeds this process's own synthetic input queue, it
    does NOT touch any other process/thread's state the way
    AttachThreadInput does, so it doesn't carry the freeze risk that got
    AttachThreadInput ruled out above."""
    hwnd = int(qwidget.winId())
    old_timeout = wintypes.DWORD(0)
    user32.SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, ctypes.byref(old_timeout), 0)
    user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, 0, 0)
    try:
        user32.keybd_event(VK_MENU, 0, 0, None)              # Alt down
        user32.keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, None)  # Alt up

        if qwidget.isMinimized():
            qwidget.showNormal()

        ok = user32.SetForegroundWindow(hwnd)
        if not ok:
            logmsg("=== force_window_to_foreground: SetForegroundWindow declined even after the Alt-keypress trick (window stays open, just not raised) ===")
        # Cheap Qt-level fallbacks - cost nothing, occasionally succeed even
        # when the raw WinAPI call above is declined.
        qwidget.raise_()
        qwidget.activateWindow()
    finally:
        user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, old_timeout.value, 0)
