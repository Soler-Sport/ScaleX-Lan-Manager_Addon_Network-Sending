import os
import shutil
import time

from . import app_controller
from . import config
from .capture import _capture_and_emit, _copy_chitu_hook_sidecar, _finish_goo_v5_capture, _wait_for_stable_file
from .logs import logmsg


# ---------------------------------------------------------------------------
# Filesystem watcher - backstop. Catches the sliced file if it ever ends up
# in ChituManager's own SlicerFile folder some other way (e.g. someone
# runs the real ChituManager manually) even when the direct TCP request
# above is what's actually driving things day to day.
# ---------------------------------------------------------------------------
def slicer_file_watcher():
    logmsg("=== slicer_file_watcher: watching %s ===", config.SLICER_WATCH_DIR)
    seen = set()
    if os.path.isdir(config.SLICER_WATCH_DIR):
        for dirpath, _dirnames, filenames in os.walk(config.SLICER_WATCH_DIR):
            for name in filenames:
                seen.add(os.path.join(dirpath, name))

    while True:
        try:
            if os.path.isdir(config.SLICER_WATCH_DIR):
                for dirpath, _dirnames, filenames in os.walk(config.SLICER_WATCH_DIR):
                    for name in filenames:
                        if not name.lower().endswith(config.SLICE_EXTENSIONS):
                            continue
                        path = os.path.join(dirpath, name)
                        if path in seen:
                            continue
                        seen.add(path)

                        _wait_for_stable_file(path, max_polls=30)  # up to ~6s

                        try:
                            os.makedirs(config.RECEIVED_DIR, exist_ok=True)
                            dest = os.path.join(config.RECEIVED_DIR, os.path.basename(path))
                            shutil.copy2(path, dest)
                            logmsg("=== SLICER FILE CAPTURED: %s -> %s (%d bytes) ===",
                                   path, dest, os.path.getsize(dest))
                            _copy_chitu_hook_sidecar(path, dest)
                        except Exception as e:
                            logmsg("=== SLICER FILE CAPTURE FAILED: %s (%s) ===", path, e)
                            continue

                        app_controller.controller.file_captured.emit(dest, None)
        except Exception as e:
            logmsg("=== slicer_file_watcher error: %s ===", e)
        time.sleep(config.POLL_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Second backstop, 2026-09-09 - catches a PENDING_DIR file CHITUBOX actually
# finished writing even when the TCP connection that requested it died
# first (see PENDING_ORPHAN_GRACE_SEC's own comment above for why this
# happens - a slice that outlives CHITUBOX's own ~5-6 min connection-reset
# window orphans handle_client()'s in-flight SaveFile request). Deliberately
# NOT tied to how long the slice actually takes: this only reacts to what's
# sitting on disk, so it works the same whether a job takes 10 seconds or
# 20 minutes.
# ---------------------------------------------------------------------------
def _pending_dir_watcher_pass(seen):
    """One scan of PENDING_DIR - pulled out of _pending_dir_watcher()'s own
    while loop so it's directly callable (and testable) without needing to
    run that infinite loop. Mutates `seen` in place, same contract as
    slicer_file_watcher() above.

    Reuses the exact same seen-set + stability-wait shape as
    slicer_file_watcher(), and the same _capture_and_emit()/
    _finish_goo_v5_capture() helpers handle_client() itself calls - not a
    parallel reimplementation of capture logic, just a second way of
    noticing a file is ready.

    No special coordination needed against the live handle_client() path:
    _capture_and_emit() removes its own PENDING copy immediately after a
    successful capture, so by the time this pass's PENDING_ORPHAN_GRACE_SEC
    age gate plus its own stability wait finish, a file the live connection
    already claimed is simply gone from disk - this only ever acts on what
    the live path never got to. The age gate is what keeps this from ever
    racing a live, still-connected capture in the first place (those
    normally finish in seconds, per slm_chitu_send.log)."""
    if not os.path.isdir(config.PENDING_DIR):
        return
    for name in os.listdir(config.PENDING_DIR):
        if name.startswith("v5_"):
            # goo_hook.dll's own converted sibling of another candidate in
            # this same directory (see rename_with_v5_prefix() in
            # goo_hook.c) - never a fresh request in its own right.
            # Whichever code path is actually waiting on THAT candidate
            # (either handle_client()'s own _finish_goo_v5_capture thread,
            # or this watcher's own handling of the non-prefixed candidate
            # below) is responsible for it; treating it as a second,
            # independent top-level file here would just waste a full 60s
            # wait on a nonsensical double-prefixed "v5_v5_..." lookup.
            continue
        if not name.lower().endswith(config.SLICE_EXTENSIONS):
            # 2026-09-25: ChituHook/goo_hook's own <basename>.json sidecar
            # (see read_chitu_hook_model_names) lands right next to its .ctb
            # in this same directory - not a slice file, and this watcher
            # has no live connection to remove it once _capture_and_emit()
            # copies its .ctb sibling into RECEIVED_DIR, so it just sits
            # here until PENDING_ORPHAN_GRACE_SEC and got mistaken for an
            # orphaned capture, opening the picker on the .json itself.
            continue
        path = os.path.join(config.PENDING_DIR, name)
        if path in seen or not os.path.isfile(path):
            continue
        try:
            age = time.time() - os.path.getmtime(path)
        except OSError:
            continue
        if age < config.PENDING_ORPHAN_GRACE_SEC:
            # Still well within the live connection's normal window - not
            # our business yet, don't mark it "seen" either so we re-check
            # its age next pass.
            continue
        seen.add(path)

        _wait_for_stable_file(path, max_polls=30)  # up to ~6s extra margin
        if not os.path.isfile(path):
            # The live connection claimed and removed it right as we were
            # about to - the rare near-miss, nothing to do.
            continue

        logmsg("=== PENDING_DIR watcher: orphaned capture found "
               "(untouched for %.0fs - connection likely died mid-slice): %s ===",
               age, path)
        if path.lower().endswith(".goo"):
            _finish_goo_v5_capture(path, None)
        else:
            _capture_and_emit(path, None)


def _pending_dir_watcher():
    logmsg("=== _pending_dir_watcher: watching %s (orphan grace period %ds) ===",
           config.PENDING_DIR, config.PENDING_ORPHAN_GRACE_SEC)
    seen = set()
    if os.path.isdir(config.PENDING_DIR):
        for name in os.listdir(config.PENDING_DIR):
            seen.add(os.path.join(config.PENDING_DIR, name))

    while True:
        try:
            _pending_dir_watcher_pass(seen)
        except Exception as e:
            logmsg("=== _pending_dir_watcher error: %s ===", e)
        time.sleep(config.POLL_INTERVAL_SEC)
