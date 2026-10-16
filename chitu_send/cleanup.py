import os
import time

from . import config
from .logs import logmsg


# ---------------------------------------------------------------------------
# Disk cleanup - RECEIVED_DIR is a real backup of every file ever sent, kept
# around for a while (resending, checking what went out, debugging a failed
# send) but not forever; PENDING_DIR should be near-empty already now that
# handle_client() removes its own staging copies right after use, but this
# also mops up anything left over from before that fix, or from any future
# case where that immediate delete fails. See RECEIVED_RETENTION_DAYS above.
# ---------------------------------------------------------------------------
def _cleanup_old_captures():
    cutoff = time.time() - config.RECEIVED_RETENTION_DAYS * 86400
    total_removed = 0
    total_freed = 0
    for d in (config.RECEIVED_DIR, config.PENDING_DIR):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            path = os.path.join(d, name)
            try:
                if not os.path.isfile(path):
                    continue
                st = os.stat(path)
                if st.st_mtime < cutoff:
                    size = st.st_size
                    os.remove(path)
                    total_removed += 1
                    total_freed += size
            except OSError as e:
                logmsg("=== _cleanup_old_captures: failed to remove %s: %s ===", path, e)
    if total_removed:
        logmsg("=== _cleanup_old_captures: removed %d file(s), freed %.1f MB (older than %d days) ===",
               total_removed, total_freed / (1024 * 1024), config.RECEIVED_RETENTION_DAYS)


def _received_dir_cleanup_loop():
    while True:
        try:
            _cleanup_old_captures()
        except Exception as e:
            logmsg("=== _received_dir_cleanup_loop error: %s ===", e)
        time.sleep(config.RETENTION_SWEEP_INTERVAL_SEC)
