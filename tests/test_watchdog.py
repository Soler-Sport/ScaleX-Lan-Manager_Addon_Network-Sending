"""The hang watchdog must write every thread's stack into the log when the GUI thread stops
re-arming it - from a C-level timer, so it works even when the GIL is held elsewhere."""
import faulthandler
import time

from chitu_send import logs, watchdog


def test_stack_dump_is_written_when_the_gui_thread_stops_rearming(tmp_path, monkeypatch):
    log_file = open(tmp_path / "hang.log", "w+", encoding="utf-8")
    monkeypatch.setattr(logs, "_logf", log_file)
    try:
        timer = watchdog._start_hang_watchdog(dump_after=0.3)  # noqa: F841 - kept alive on purpose
        time.sleep(1.2)  # no event loop here, so nothing re-arms the timer: a wedged GUI thread
        log_file.flush()
        log_file.seek(0)
        text = log_file.read()
    finally:
        faulthandler.cancel_dump_traceback_later()
        faulthandler.disable()
        log_file.close()

    assert "Timeout" in text and "most recent call first" in text


def test_no_dump_while_the_timer_keeps_being_rearmed(tmp_path, monkeypatch):
    log_file = open(tmp_path / "ok.log", "w+", encoding="utf-8")
    monkeypatch.setattr(logs, "_logf", log_file)
    try:
        watchdog._start_hang_watchdog(dump_after=5.0)
        time.sleep(0.2)
        faulthandler.cancel_dump_traceback_later()
        log_file.flush()
        log_file.seek(0)
        text = log_file.read()
    finally:
        faulthandler.cancel_dump_traceback_later()
        faulthandler.disable()
        log_file.close()

    assert "Timeout" not in text
