import json
import os
import threading
import time
import uuid

from . import app_controller
from . import capture
from . import config
from .capture import _capture_and_emit, _finish_goo_v5_capture, _wait_for_stable_file
from .logs import _redact_secrets, logmsg


# ---------------------------------------------------------------------------
# CHITUBOX TCP protocol - the real trigger. CHITUBOX itself understands a
# "SaveFile" message: {"MsgType":"SaveFile","FilePath":"<path>"} tells it to
# write (or copy its already-sliced internal file to) exactly that path, no
# ChituManager/UI/login/printer-selection involved at all (confirmed via
# Ghidra decompile of CHITUBOX Pro.exe's own ChituManager::saveSliceFile /
# ChituManager::saveSlicerFileOver, 2026-08-19). We ask for this the moment
# CHITUBOX tells us it's ready (LoadWindow) and just wait for the reply.
# ---------------------------------------------------------------------------
def extract_field(buf, marker):
    # 2026-09-08 (code-review fix, finding #8): this protocol has no message
    # framing beyond ad-hoc newline-joined JSON blobs, and a single
    # conn.recv() chunk can contain more than one CHITUBOX message
    # concatenated together (REQUEST_COOLDOWN_SEC's own comment already
    # acknowledges CHITUBOX sends "retry-burst pings"). rfind (last match)
    # instead of find (first match) picks the most RECENT occurrence in the
    # chunk rather than the earliest/possibly-stale one - e.g. an older
    # WindowProperty message concatenated before the current one would
    # otherwise silently win for fields like PrinterType/SliceFileName.
    idx = buf.rfind(marker)
    if idx < 0:
        return None
    start = idx + len(marker)
    end = buf.find('"', start)
    if end < 0:
        return None
    return buf[start:end]


LOADWINDOW_REPLY = (
    "{\n"
    "    \"Handle\": \"network_send\",\n"
    "    \"MsgType\": \"LoadWindow\",\n"
    "    \"Result\": true,\n"
    "    \"WinType\": 1\n"
    "}\n"
).encode("utf-8")


# 2026-09-08 (experimental): slm_chitu_send's own picker window is a totally
# separate native Qt window, not anything CHITUBOX renders itself - as far
# as CHITUBOX is concerned, every "LoadWindow" ping (sent on every
# "Отправка по сети" click) just gets the same static Result:true reply
# above, whether or not we actually showed anything, and we've never sent
# CHITUBOX anything back when that window later closes. Confirmed live
# 2026-09-08: after one successful capture cycle, further clicks stopped
# producing a "Visible": true LoadWindow at all - CHITUBOX kept sending
# "SlicerInfo" + "LoadWindow Visible:false" pings for over an hour instead,
# exactly matching the "button does nothing, second click or Save Slice
# works" report (Save Slice never touches this handshake at all, via
# slicer_file_watcher()). Hypothesis: CHITUBOX's own side still believes
# the network-send window is open from the last click (we told it
# Result:true and never said otherwise), so it toggles instead of
# reopening. Unverified against CHITUBOX's real protocol - sent
# unprompted (not a reply to anything) when PickerWindow.closeEvent fires,
# see there.
LOADWINDOW_CLOSE_NOTIFY = (
    "{\n"
    "    \"Handle\": \"network_send\",\n"
    "    \"MsgType\": \"LoadWindow\",\n"
    "    \"Result\": true,\n"
    "    \"Visible\": false,\n"
    "    \"WinType\": 1\n"
    "}\n"
).encode("utf-8")


REQUEST_COOLDOWN_SEC = 4.0  # collapse CHITUBOX's retry-burst pings into one request


class _ChituboxConn:
    """2026-09-08 (code-review fix, findings #4/#5): thread-safe wrapper
    around one CHITUBOX TCP connection. Before this, handle_client()'s own
    background thread called conn.send()/conn.close() directly, and
    PickerWindow.closeEvent() (GUI thread) independently called
    conn.send(LOADWINDOW_CLOSE_NOTIFY) on the very same socket with no
    coordination between the two threads at all - a genuine race (two
    concurrent sends could interleave on the wire; a send racing a close
    hits platform-dependent behavior) papered over only by catching
    OSError for the common "already closed" case, not the rarer true
    concurrent-access case.

    recv() is deliberately NOT lock-protected: handle_client() is the only
    reader, ever, so there is no race to guard there, and serializing it
    behind the same lock sends use would let a slow/blocked send stall the
    read loop (or vice versa) for zero correctness benefit.

    close() is idempotent, so a send arriving after close() (from either
    thread) is just a normal, expected "connection already gone" - not a
    race - and returns False instead of raising."""

    def __init__(self, conn):
        self._conn = conn
        self._lock = threading.Lock()
        self._closed = False

    def send(self, data):
        """Best-effort - True on success, False if already closed or the
        send itself failed (caller decides whether/how loudly to log)."""
        with self._lock:
            if self._closed:
                return False
            try:
                self._conn.send(data)
                return True
            except OSError:
                return False

    def recv(self, bufsize):
        return self._conn.recv(bufsize)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._conn.close()
            except OSError:
                pass


_JUPITER2_PRINTER_TYPES = ("elegoo jupiter 2",)  # exact (normalized) values


# 2026-10-13: CHITUBOX silently drops ~15% of our SaveFile requests - never
# even calls saveSliceFile (goo_hook writes the sidecar JSON at the START of
# that call, and it's absent for every dropped request), then answers only
# when the operator saves by hand. No logged state predicts it (open
# pickers, last Visible flag, repeated slice, fresh SlicerInfo and prior
# close notices were all ruled out), but dropped requests were slightly more
# common when the request followed our LoadWindow reply within the same
# millisecond (20% at 0 ms, 12% at 1 ms, 0 of 3 at 2+ ms) - so the request
# now goes out a beat after the reply, and if CHITUBOX still doesn't start
# saving it is re-sent (see _request_save_with_retry).
# Capture of the STOCK ChituManager (tools/chitu_loopback_sniffer.py,
# 2026-10-13) showed it sends the byte-identical {"FilePath":..,"MsgType":
# "SaveFile"} request, but never sooner than 2.6 s after the click (the
# operator is still choosing printers), answers each LoadWindow ping 10-30 ms
# later, and gets exactly one ping per click - while episodes where our
# requests were ignored show bursts of repeated pings. So: request no sooner
# than SAVE_REQUEST_DELAY_SEC after the click, answer pings after
# LOADWINDOW_REPLY_DELAY_SEC.
SAVE_REQUEST_DELAY_SEC = 2.0


LOADWINDOW_REPLY_DELAY_SEC = 0.02


SAVE_ACCEPT_WAIT_SEC = 3.0


SAVE_WATCH_POLL_SEC = 0.2


SAVE_MAX_RETRIES = 2


def _request_save_with_retry(chandle, state, slice_label, ext, retries_left=None, replaces=None):
    """Runs on its own thread (handle_client's recv loop must stay free).
    Sends one SaveFile request, then watches for CHITUBOX actually starting
    the save: goo_hook writes <target>.json the moment saveSliceFile begins,
    and the target file itself appears once data is flowing. Neither within
    SAVE_ACCEPT_WAIT_SEC means the request was dropped - re-send with a
    fresh name. Retries only once the hook has been seen working this run
    (_hook_sidecar_seen): without that signal "dropped" can't be told apart
    from "slow", and a blind re-send could double-save a big file.
    state["awaiting"] (guarded by state["lock"]) is the shared "which
    request is the reply for": a reply clears it only if it still names this
    request, and a re-send (replaces=<previous target>) only goes out if it
    still does - so a newer click or a late reply during the delay/sleep
    can't be clobbered (found in review 2026-10-13)."""
    if retries_left is None:
        retries_left = SAVE_MAX_RETRIES
    try:
        if replaces is None and app_controller.controller is not None:
            app_controller.controller.save_requested.emit(slice_label)  # immediate "click registered" feedback, once per click
        time.sleep(SAVE_REQUEST_DELAY_SEC)
        target = os.path.join(config.PENDING_DIR, "%s_%s%s" % (slice_label, uuid.uuid4().hex[:8], ext))
        with state["lock"]:
            if replaces is not None and state["awaiting"] != replaces:
                return  # answered, or superseded by a newer click, while we waited
            state["awaiting"] = target
        request = json.dumps({"MsgType": "SaveFile", "FilePath": target.replace("\\", "/")})
        if not chandle.send((request + "\n").encode("utf-8")):
            logmsg("=== SaveFile request NOT sent (connection closed) for %s ===", slice_label)
            with state["lock"]:
                if state["awaiting"] == target:
                    state["awaiting"] = None
            return
        logmsg("=== REQUESTED SaveFile: %s ===", target)

        sidecar = os.path.splitext(target)[0] + ".json"
        deadline = time.monotonic() + SAVE_ACCEPT_WAIT_SEC
        while time.monotonic() < deadline:
            if state["awaiting"] != target:
                return
            if os.path.exists(sidecar):
                capture._hook_sidecar_seen = True
                return
            if os.path.exists(target):
                return
            time.sleep(SAVE_WATCH_POLL_SEC)
        if state["awaiting"] != target or not capture._hook_sidecar_seen:
            return
        if retries_left <= 0:
            logmsg("=== CHITUBOX ignored the SaveFile request and %d re-sends for %s ===",
                   SAVE_MAX_RETRIES, slice_label)
            return
        logmsg("=== CHITUBOX didn't start saving %s within %.0fs - re-sending (%d left) ===",
               os.path.basename(target), SAVE_ACCEPT_WAIT_SEC, retries_left)
        _request_save_with_retry(chandle, state, slice_label, ext, retries_left - 1, replaces=target)
    except Exception as e:
        logmsg("=== _request_save_with_retry FAILED: %s ===", e)


def handle_client(conn, addr):
    logmsg("=== CLIENT CONNECTED from %s:%d ===", addr[0], addr[1])
    chandle = _ChituboxConn(conn)  # 2026-09-08 (code-review fix, findings #4/#5) - see its own docstring
    last_request_ts = 0.0
    state = {"awaiting": None, "lock": threading.Lock()}  # path of the SaveFile request a reply would answer - shared with _request_save_with_retry's thread
    slice_label = "network_send"
    printer_type = ""  # 2026-09-08: from CHITUBOX's own "PrinterType" JSON
    # field (same WindowProperty payload as SliceFileName) - gates whether
    # we request ".goo" (only correct for ELEGOO Jupiter 2, whose v3 output
    # goo_hook.dll knows how to convert to real v5) vs the original ".ctb"
    # for every other printer (e.g. Saturn 4 Ultra 16K, which is used as
    # .ctb only - CHITUBOX's raw v3 bytes under a ".goo" name for a printer
    # goo_hook.dll doesn't know about would be silently wrong). Persists for
    # the whole connection (CHITUBOX doesn't necessarily resend it on every
    # single ping) - see the empty-value warning below for the one edge
    # case that doesn't cover (code-review finding #6).
    try:
        while True:
            chunk = chandle.recv(65536)
            if not chunk:
                break
            try:
                text = chunk.decode("utf-8", "replace")
            except Exception:
                text = ""
            logmsg("RECV(%d): %s", len(chunk), _redact_secrets(text)[:800])

            label = extract_field(text, '"SliceFileName": "')
            if label:
                slice_label = os.path.splitext(label)[0]

            pt = extract_field(text, '"PrinterType": "')
            if pt:
                printer_type = pt

            # The reply to our own SaveFile request: {"MsgType":"SaveFile","Data":{"SavePath":...}}
            if '"MsgType": "SaveFile"' in text and state["awaiting"]:
                awaiting_path = state["awaiting"]
                save_path = extract_field(text, '"SavePath": "')
                logmsg("=== SaveFile reply: SavePath=%s (awaiting=%s) ===", save_path, awaiting_path)
                candidate = save_path or awaiting_path
                candidate = candidate.replace("/", os.sep)
                # Real, recurring race confirmed live 2026-08-31 ("SaveFile
                # reply but file not found", 7 occurrences across several
                # days in the log - matches the "first click doesn't open
                # the picker, second click works fine" report): CHITUBOX's
                # own SaveFile JSON confirmation can arrive slightly before
                # the actual write to disk is done/flushed, especially for
                # a large slice file - a single immediate isfile() check
                # can lose that race and give up entirely, with no retry.
                # Wait for the file to actually appear, then (mirroring
                # slicer_file_watcher()'s own size-stability wait) for its
                # size to stop changing, before trusting it's really there
                # and complete. Safe to block this thread for a few
                # seconds - handle_client() runs on its own thread per
                # connection now, this can't stall accepting new ones.
                _wait_for_stable_file(candidate, max_polls=25)  # up to ~5s

                # 2026-09-08: only ELEGOO Jupiter 2 requests are ever named
                # ".goo" (see the request-building code below) - that's the
                # only case goo_hook.dll's DirWatcher will pick up and
                # convert v3->v5, renaming the result to "v5_<original
                # name>" in the SAME directory once done (see
                # rename_with_v5_prefix() in goo_hook.c), which renames
                # `candidate` itself away out from under us. For every
                # other printer (.ctb request), nothing will ever touch
                # this file - skip straight to capturing it as-is.
                #
                # 2026-09-08 (code-review fix, finding #10): the .goo wait
                # itself now runs on its own thread (_finish_goo_v5_capture)
                # instead of blocking this connection's own recv() loop for
                # up to 60s - see that function's docstring.
                if candidate.lower().endswith(".goo"):
                    threading.Thread(target=_finish_goo_v5_capture, args=(candidate, chandle), daemon=True).start()
                elif os.path.isfile(candidate):
                    _capture_and_emit(candidate, chandle)
                else:
                    logmsg("=== SaveFile reply but file not found at %s ===", candidate)
                with state["lock"]:
                    if state["awaiting"] == awaiting_path:  # a newer request may have replaced it meanwhile
                        state["awaiting"] = None

            if '"MsgType": "LoadWindow"' in text and '"WinType"' in text:
                time.sleep(LOADWINDOW_REPLY_DELAY_SEC)  # the stock manager answers 10-30 ms after the ping
                ok = chandle.send(LOADWINDOW_REPLY)
                logmsg("%s (%d bytes) LoadWindow reply", "SENT" if ok else "SEND FAILED", len(LOADWINDOW_REPLY))

                if '"Visible": true' in text:
                    now = time.monotonic()
                    if now - last_request_ts >= REQUEST_COOLDOWN_SEC:
                        last_request_ts = now
                        os.makedirs(config.PENDING_DIR, exist_ok=True)
                        # 2026-09-08: request ".goo" ONLY for ELEGOO Jupiter
                        # 2 - goo_hook.dll's own DirWatcher (which
                        # recursively watches every drive for *.goo
                        # activity, not just the normal Save Slice folder)
                        # picks a *.goo file up and converts it v3->v5 in
                        # place, but that v5 header/table layout is only
                        # valid for Jupiter 2's real panel - CHITUBOX just
                        # writes whatever native (v3) bytes it has to
                        # whatever path we hand it regardless of extension,
                        # so naming any OTHER printer's output ".goo" would
                        # make goo_hook.dll wrongly "convert" it too. Every
                        # other printer (e.g. Saturn 4 Ultra 16K, used as
                        # .ctb only) keeps the original ".ctb" behavior,
                        # completely unchanged. See the SaveFile-reply
                        # handling below for how we wait for goo_hook's
                        # conversion (and its "v5_" rename) to finish
                        # before treating a Jupiter-2 file as ready to send.
                        #
                        # 2026-09-08 (code-review fix, finding #7): exact
                        # match against known values, not a substring check -
                        # printer_matches_machine() (see above) deliberately
                        # avoids substring matching for the identical reason
                        # ("Saturn 4 Ultra" vs "Saturn 4 Ultra 16K" - a
                        # substring check matches both). A hypothetical
                        # future "Jupiter 2 Pro"/"Jupiter 2 Max" PrinterType
                        # would otherwise silently get routed through a
                        # conversion pipeline that's only valid for the real
                        # Jupiter 2 panel.
                        printer_type_norm = printer_type.strip().lower()
                        is_jupiter2 = printer_type_norm in _JUPITER2_PRINTER_TYPES
                        if not printer_type_norm:
                            # 2026-09-08 (code-review fix, finding #6): no
                            # PrinterType has been seen on this connection
                            # yet (e.g. this is the very first click before
                            # any WindowProperty/SlicerInfo message
                            # arrived). Defaulting to .ctb is the SAFER of
                            # the two possible wrong guesses (a wrong .goo
                            # would make goo_hook.dll "convert" a different
                            # printer's output), but it's still a guess -
                            # log it loudly so a future "doesn't work for
                            # Jupiter 2 on the very first click" report is
                            # diagnosable from the log instead of a mystery.
                            logmsg("  -> WARNING: no PrinterType seen yet on this connection - "
                                   "defaulting to .ctb (would be wrong for ELEGOO Jupiter 2)")
                        ext = ".goo" if is_jupiter2 else ".ctb"
                        threading.Thread(target=_request_save_with_retry,
                                         args=(chandle, state, slice_label, ext), daemon=True).start()
                    else:
                        logmsg("  -> Visible:true within cooldown (%.1fs ago), not requesting again",
                               now - last_request_ts)
    finally:
        logmsg("=== CLIENT DISCONNECTED ===")
        chandle.close()


def _chitubox_accept_loop(listen_sock):
    while True:
        try:
            conn, addr = listen_sock.accept()
        except Exception as e:
            logmsg("=== CHITUBOX accept() FAILED, listener socket is likely dead: %s ===", e)
            return

        # handle_client() used to run right here, synchronously, blocking
        # this accept() loop for as long as that one connection stayed
        # open - fine for the normal case (CHITUBOX keeps one persistent
        # connection for its whole runtime), but it meant a connection
        # that went stale WITHOUT a clean close (CHITUBOX crashed, the
        # machine slept/resumed, a network blip) left conn.recv() blocked
        # forever on a peer that no longer exists, and the listener could
        # never accept() a new connection again - slm_chitu_send would go
        # completely deaf until manually restarted. Confirmed live
        # 2026-08-27: "Отправка по сети" stopped opening the picker
        # entirely (the slicer_file_watcher backstop still worked fine,
        # since it doesn't touch this socket at all) - exactly this
        # failure mode, flagged as a known gap back when this loop was
        # first reviewed but not fixed until it actually happened. Each
        # connection now gets its own thread so accept() is always free to
        # take the next one immediately, however long (or however dead)
        # any previous connection turns out to be. handle_client() only
        # ever touches its own local state per call, nothing shared that
        # would need a lock across connections.
        def _serve(conn=conn, addr=addr):
            try:
                handle_client(conn, addr)
            except Exception as e:
                # A single bad connection (CHITUBOX closed unexpectedly, a
                # malformed message, whatever) must not take down the
                # whole listener.
                logmsg("=== handle_client FAILED for %s:%d: %s ===", addr[0], addr[1], e)

        threading.Thread(target=_serve, daemon=True).start()
