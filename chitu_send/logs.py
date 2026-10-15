import datetime
import os
import re
import threading

from . import config


os.makedirs(config.ROOT_DIR, exist_ok=True)


_log_lock = threading.Lock()


_logf = open(config.LOG_PATH, "a", encoding="utf-8", newline="")


def logmsg(fmt, *args):
    line = fmt % args if args else fmt
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with _log_lock:
        _logf.write("[%s] %s\r\n" % (ts, line))
        _logf.flush()
    print("[%s] %s" % (ts, line))


# their live round-trip in seconds to low tens of seconds per
# slm_chitu_send.log's own timings; this only needs to be comfortably shorter
# than the ~5-6 min reset window and comfortably longer than normal
# variance, not tightly tuned.


_SECRET_FIELD_RE = re.compile(r'("(?:password|cookie)"\s*:\s*)"(?:[^"\\]|\\.)*(?:"|$)', re.IGNORECASE)


def _redact_secrets(text):
    """CHITUBOX's Init message carries the account's Password (plain text)
    and Cookie - found sitting in slm_chitu_send.log 2026-10-13. Everything
    that logs a raw CHITUBOX message goes through this first."""
    return _SECRET_FIELD_RE.sub(r'\1"***"', text)
