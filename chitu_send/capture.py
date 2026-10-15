import os
import shutil
import time

from . import app_controller
from . import config
from .logs import logmsg


def _wait_for_stable_file(path, max_polls, poll_interval=0.2):
    """Polls up to `max_polls` times (poll_interval seconds apart) until
    `path` exists and its size stops changing between two consecutive
    checks - a cheap, portable way to wait out a still-in-progress write
    without any OS-specific file-lock API. Returns as soon as it looks
    stable; otherwise just runs out the full time budget. Callers still do
    their own final existence check afterward - this only waits, it
    doesn't decide anything.

    Shared by handle_client()'s SaveFile-reply race fix (CHITUBOX's own
    confirmation can arrive slightly before the write is actually flushed
    to disk, especially for a large file - confirmed live 2026-08-31, 7
    "SaveFile reply but file not found" occurrences across several days,
    matching the "first click doesn't open the picker, second click works"
    report) and slicer_file_watcher()'s backstop path, which already had
    this exact wait inline (pre-existing, not new here) before this got
    pulled out as a shared helper.

    Known limitation, inherited unchanged from that original inline
    version: "stable" only means two consecutive polls saw the same size,
    so a writer that pauses mid-write for longer than poll_interval could
    in principle be mistaken for finished. Not a new risk introduced here,
    and not something CHITUBOX's own write pattern has ever shown live -
    worth knowing about, not worth a bigger redesign for the bug this
    fixes."""
    last_size = -1
    for _ in range(max_polls):
        try:
            size = os.path.getsize(path) if os.path.isfile(path) else -1
        except OSError:
            size = -1
        if size == last_size and size > 0:
            return
        last_size = size
        time.sleep(poll_interval)


_V5CONVERT_FLAG_PATH = r"C:\ChituHook\chitu_hook_v5convert.flag"


# seen live in CHITUBOX's own "PrinterType" field - see is_jupiter2 below


def _goo_hook_convert_enabled():
    """Mirrors goo_hook.c's own V5_IsConvertEnabled() exactly: same flag
    file, same semantics (missing file, or content not starting with '0',
    means enabled). 2026-09-08 (code-review fix, finding #3): lets
    handle_client()/_finish_goo_v5_capture() skip the wait for a v5 sibling
    entirely when the user has the "Convert to GOO v5" tray toggle off -
    goo_hook.c's process_finished_goo() returns immediately, writing
    nothing, in that case, so the old code always burned the full 60s
    deadline for a sibling that could never appear."""
    try:
        with open(_V5CONVERT_FLAG_PATH, "rb") as f:
            c = f.read(1)
    except OSError:
        return True  # missing file -> enabled, matching goo_hook.c exactly
    return c != b"0"


def _looks_like_native_v3_goo(path):
    """True if `path` still starts with the v3 magic tag ("V3.0") - i.e.
    goo_hook.dll either hasn't touched it yet or never will. 2026-09-08
    (code-review fix, finding #2): goo_hook.c's process_finished_goo()
    reopens this exact path with CREATE_ALWAYS (truncating it) right before
    writing v5 bytes, and only renames it away once fully written - so
    there's a real, if narrow (a single WriteFile call), window where the
    file exists on disk but is truncated/mid-rewrite. Checking the magic
    bytes before trusting a post-deadline fallback read is cheap insurance
    against forwarding a corrupt partial file caught in that window."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"V3.0"
    except OSError:
        return False


def _copy_chitu_hook_sidecar(send_path, dest):
    """Best-effort copy of ChituHook/goo_hook's own sidecar <basename>.json
    (see read_chitu_hook_model_names/match_composition_components and
    PickerWindow's "Состав" panel) from next to send_path to next to dest,
    so it survives send_path's own removal a few lines below in every
    _capture_and_emit() caller. A missing sidecar (hook disabled/not
    installed, or an older capture from before this feature) is the normal
    case, not an error."""
    global _hook_sidecar_seen
    src_json = os.path.splitext(send_path)[0] + ".json"
    if not os.path.isfile(src_json):
        return
    _hook_sidecar_seen = True
    dest_json = os.path.splitext(dest)[0] + ".json"
    try:
        shutil.copy2(src_json, dest_json)
    except OSError as e:
        logmsg("=== failed to copy ChituHook sidecar %s: %s ===", src_json, e)


def _capture_and_emit(send_path, chandle):
    """Shared by handle_client()'s two SaveFile-reply capture paths (plain
    .ctb inline; Jupiter-2 .goo on its own thread, see
    _finish_goo_v5_capture below) - 2026-09-08 (code-review cleanup, pulled
    out of what used to be duplicated inline in both places). Copies
    send_path into RECEIVED_DIR, removes the PENDING staging copy, and
    emits file_captured so the picker opens on the GUI thread. chandle is
    the _ChituboxConn this capture came from (None from
    slicer_file_watcher()'s backstop path, which has no connection)."""
    try:
        os.makedirs(config.RECEIVED_DIR, exist_ok=True)
        dest = os.path.join(config.RECEIVED_DIR, os.path.basename(send_path))
        shutil.copy2(send_path, dest)
        logmsg("=== CTB CAPTURED via direct request: %s -> %s (%d bytes) ===",
               send_path, dest, os.path.getsize(dest))
        _copy_chitu_hook_sidecar(send_path, dest)
        # send_path (in PENDING_DIR) was only ever a staging copy for
        # CHITUBOX/goo_hook to write into - dest (in RECEIVED_DIR) is the
        # real, permanent one. Nothing ever reads it again once this copy
        # has succeeded, so leaving it in place just double-counts every
        # capture's disk footprint for no reason.
        try:
            os.remove(send_path)
        except OSError as e:
            logmsg("=== failed to remove PENDING copy %s after capture: %s ===", send_path, e)
        app_controller.controller.file_captured.emit(dest, chandle)
    except Exception as e:
        logmsg("=== capture after SaveFile reply FAILED: %s (%s) ===", send_path, e)


def _finish_goo_v5_capture(candidate, chandle):
    """Runs on its own daemon thread - spawned from handle_client() only for
    the ELEGOO Jupiter 2 .goo case. 2026-09-08 (code-review fix, finding
    #10): the up-to-60s wait for goo_hook.dll's v5-converted sibling used to
    run inline in handle_client()'s own per-connection thread, blocking
    that connection's conn.recv() loop for up to a minute per Jupiter-2
    capture - CHITUBOX keeps one persistent connection for its whole
    runtime, so any further message it sent on that same socket during the
    wait (a second click, a PrinterType/SliceFileName update) just sat
    unread until the wait finished. Moving the wait here lets
    handle_client() go straight back to conn.recv() instead.

    Deliberately has no bare/undecorated body: back when this ran inline in
    handle_client(), an unexpected exception here would propagate up
    through handle_client()'s own try/finally and get logged by
    _chitubox_accept_loop()'s wrapper ("handle_client FAILED ..."). Running
    on its own bare thread instead means an uncaught exception here would
    otherwise just die silently via Python's default thread excepthook -
    invisible in slm_chitu_send.log, the only place this app's failures are
    ever actually looked for. See the try/except wrapping the whole body
    below (2026-09-08, second-pass code-review fix)."""
    try:
        _finish_goo_v5_capture_body(candidate, chandle)
    except Exception as e:
        logmsg("=== _finish_goo_v5_capture FAILED for %s: %s ===", candidate, e)


def _finish_goo_v5_capture_body(candidate, chandle):
    v5_candidate = os.path.join(os.path.dirname(candidate), "v5_" + os.path.basename(candidate))

    if not _goo_hook_convert_enabled():
        logmsg("=== goo_hook v3->v5 conversion is disabled (tray toggle) - "
               "skipping the wait for a v5 sibling of %s ===", candidate)
    else:
        # Real jobs have taken up to ~25s parallelized per goo_hook's own
        # timing logs - give it real margin.
        v5_deadline = time.monotonic() + 60.0
        while time.monotonic() < v5_deadline and not os.path.isfile(v5_candidate):
            time.sleep(0.5)

    if os.path.isfile(v5_candidate):
        _wait_for_stable_file(v5_candidate, max_polls=10)  # already fully written by the rename; just a safety margin
        logmsg("=== goo_hook v5-converted sibling found: %s ===", v5_candidate)
        _capture_and_emit(v5_candidate, chandle)
        return

    # No v5 sibling - fall back to the original file, but (finding #2) only
    # if it still genuinely looks like the untouched native v3 file
    # goo_hook hasn't started rewriting (or never will), not just
    # "something happens to exist at that path right now".
    if os.path.isfile(candidate) and _looks_like_native_v3_goo(candidate):
        logmsg("=== WARNING: no v5_-prefixed sibling appeared for %s - "
               "sending CHITUBOX's native v3 file as-is (goo_hook.dll not installed/"
               "running, disabled, or conversion failed) ===", candidate)
        _capture_and_emit(candidate, chandle)
    else:
        logmsg("=== SaveFile reply: no usable file left at %s after waiting for goo_hook "
               "(missing, or caught mid-rewrite) ===", candidate)


_hook_sidecar_seen = False  # set once any save produced goo_hook's sidecar JSON - proof the "started saving" signal works
