import json
import os
import threading

from .logs import logmsg
from .scalex import build_recommendation_patch, ctb_params, fetch_printers, forward_to_scalex, has_recommendations, patch_and_upload_single, poll_scalex_upload, start_stored_file


def send_in_background(file_path, targets, display_name=None, start_print=False, report_cb=None,
                       test_print=False):
    """targets: list of {"printerId": id, "applyRecommendations": bool}.
    test_print: mark every upload as a test print («без учёта склада») -
    see forward_to_scalex.
    display_name: filename to present to ScaleX (defaults to the file's own
    name on disk) - lets the picker page rename the file before sending,
    same idea as ChituManager's own editable filename field.
    start_print: whether to actually start printing once each transfer
    lands (X-Start-Print / autoStart) - but only actually sent as such to
    printers that are operatorPrepared; for one that isn't, _send_one()
    below uploads without starting and instead registers the start via
    ScaleX's own queueIfNotPrepared mechanism (start_stored_file()) so it
    fires automatically once an operator confirms preparation, rather
    than starting blind on an unconfirmed printer or silently dropping
    the "start" request the picker was told to honor (per user request
    2026-08-27).

    ALWAYS dispatches per-printer, in parallel, through the same
    single-printer endpoints ScaleX's own normal upload UI uses
    (/api/printers/{id}/files, or /api/ctb/patch-and-upload when a
    printer's exposure actually needs patching) - never the bulk/from-draft
    endpoint. That path used to be the default here when start_print was
    False, but it's explicitly marked "experimental" in ScaleX's own API
    response and was observed live (2026-08-20) starting a real print on a
    printer despite the request carrying no start-print field at all -
    i.e. its "queue only" behaviour can't be trusted. X-Start-Print on the
    single-printer path is well-established (it's the literal mechanism
    ScaleX's own upload modal uses for its "start printing" checkbox), so
    that's the only path this uses now, for both start_print states.
    report_cb, if given, is called from a background thread as
    report_cb(phase, percent, targets) whenever the aggregate/per-printer
    progress changes - targets is [{"printerId","label","phase","percent"}, ...].
    Callers with a Qt GUI should have report_cb emit a Signal rather than
    touch widgets directly (this runs on a worker thread, not the GUI
    thread) - see PickerWindow._on_send_clicked."""
    name = display_name or os.path.basename(file_path)

    def _run():
        # The CTB draft/patch-and-upload endpoint always makes a temporary
        # rewritten copy of the file server-side before sending it - fine
        # when a printer's exposure/layer settings actually need patching,
        # wasteful (~1min, confirmed by ScaleX's own confirm() prompt for
        # this exact endpoint) when the timings in the file are already
        # correct. ScaleX's own upload UI only goes through that path when
        # there's an actual patch selected - otherwise it just streams the
        # file as-is. Mirrors that here: only fetch a draftId, and only for
        # printers that end up needing one.
        #
        # Targets are dispatched to ScaleX *concurrently*, not one at a time
        # - ScaleX's own manager already queues/throttles transfers to each
        # printer itself, slm_chitu_send doesn't need to serialize on top of
        # that (that just makes a multi-printer send take N times longer
        # than it needs to for no reason).
        if report_cb:
            report_cb("uploading", 5, [])
        try:
            printers_by_id = {str(p.get("id")): p for p in fetch_printers()}
        except Exception as e:
            printers_by_id = {}
            logmsg("=== fetch_printers FAILED (send flow): %s ===", e)

        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = None

        draft_id = [None]  # fetched lazily, only if some target actually needs a patch
        draft_lock = threading.Lock()

        def _get_draft_id():
            with draft_lock:
                if draft_id[0] is None:
                    draft = ctb_params(file_path, display_name=name)
                    draft_id[0] = draft.get("draftId")
                return draft_id[0]

        tracker = {}  # printerId -> {"label", "phase", "percent"}
        tracker_lock = threading.Lock()

        def _report():
            with tracker_lock:
                items = list(tracker.items())
            if not items:
                return
            vals = [v for _, v in items]
            pcts = [v["percent"] for v in vals if v["percent"] is not None]
            percent = (sum(pcts) / len(pcts)) if pcts else None
            all_done = all(v["phase"] in ("done", "queued_prepared", "error") for v in vals)
            any_error = any(v["phase"] == "error" for v in vals)
            phase = "error" if (all_done and any_error) else ("done" if all_done else "sending")
            targets_out = [{"printerId": pid, "label": v["label"], "phase": v["phase"], "percent": v["percent"],
                             "errorReason": v.get("errorReason")} for pid, v in items]
            if report_cb:
                report_cb(phase, percent, targets_out)

        def _send_one(t):
            pid = t["printerId"]
            printer = printers_by_id.get(str(pid), {})
            label = printer.get("displayName") or printer.get("name") or pid
            with tracker_lock:
                tracker[pid] = {"label": label, "phase": "sending", "percent": 0.0, "errorReason": None}
            _report()

            # Courtesy pre-check, not authoritative: remainingMemory is a
            # snapshot from whenever fetch_printers() above ran, another
            # job could still land on this printer between here and the
            # real upload, so ScaleX's own rejection is still the final
            # word either way - this just catches the common, obviously-
            # doomed case up front without spending any time/bandwidth on
            # a transfer that can't fit, and reports *why* instead of a
            # generic error (per user request 2026-08-25). Skips the check
            # entirely if remainingMemory isn't in this snapshot at all,
            # rather than guessing.
            if file_size is not None:
                remaining = (printer.get("status") or {}).get("remainingMemory")
                try:
                    remaining = int(remaining) if remaining is not None else None
                except (TypeError, ValueError):
                    remaining = None
                if remaining is not None and remaining < file_size:
                    logmsg("=== SKIPPED %s: insufficient printer memory (remaining=%d bytes, file=%d bytes) ===",
                           pid, remaining, file_size)
                    with tracker_lock:
                        tracker[pid]["phase"] = "error"
                        tracker[pid]["percent"] = 100.0
                        tracker[pid]["errorReason"] = "low_memory"
                    _report()
                    return

            # If a start was requested but this printer isn't marked
            # operatorPrepared, don't send X-Start-Print/autoStart=true
            # blindly (per user request 2026-08-27) - upload without
            # starting, then register the start through ScaleX's own
            # two-step "queue until prepared" mechanism instead
            # (start_stored_file(..., queue_if_not_prepared=True) below),
            # confirmed via its own app.js: same thing its own UI does
            # when you try to start an unprepared printer and choose to
            # queue it rather than cancel. A printer that IS prepared is
            # completely unaffected - same single-request flow as before.
            printer_prepared = printer.get("operatorPrepared") is True
            needs_deferred_start = bool(start_print) and not printer_prepared
            effective_start_print = bool(start_print) and not needs_deferred_start
            uploaded_path = [None]  # filled in once the initial request's own response is parsed below

            def _register_deferred_start():
                path = uploaded_path[0]
                if not path:
                    logmsg("=== %s: can't register deferred start, no lastUploadedPath in the upload response ===", pid)
                    with tracker_lock:
                        tracker[pid]["phase"] = "error"
                        tracker[pid]["percent"] = 100.0
                    _report()
                    return
                try:
                    qstatus, qbody = start_stored_file(pid, path, queue_if_not_prepared=True)
                except Exception as e:
                    logmsg("=== %s: deferred start request FAILED: %s ===", pid, e)
                    with tracker_lock:
                        tracker[pid]["phase"] = "error"
                        tracker[pid]["percent"] = 100.0
                    _report()
                    return
                logmsg("=== DEFERRED START (queueIfNotPrepared) -> %s: HTTP %d: %s ===",
                       pid, qstatus, qbody[:300].decode("utf-8", "replace"))
                with tracker_lock:
                    tracker[pid]["phase"] = "queued_prepared" if 200 <= qstatus < 300 else "error"
                    tracker[pid]["percent"] = 100.0
                _report()

            def _cb(is_terminal, is_error, job_percent, message, status):
                # patch-and-upload's own initial 202 response never carries
                # lastUploadedPath at all (confirmed live 2026-08-27 - only
                # the plain/unpatched upload's initial response does) but
                # the polled status does once ScaleX actually has it, so
                # keep grabbing it on every tick rather than relying on the
                # initial response alone.
                if status.get("lastUploadedPath"):
                    uploaded_path[0] = status["lastUploadedPath"]
                if is_terminal and not is_error and needs_deferred_start:
                    _register_deferred_start()
                    return
                with tracker_lock:
                    tracker[pid]["phase"] = "error" if is_error else ("done" if is_terminal else "sending")
                    if job_percent is not None:
                        tracker[pid]["percent"] = job_percent
                _report()

            # 2026-09-08 (code-review fix, finding #1): build_recommendation_patch
            # only ever makes sense for a real CTB file - patch_and_upload_single
            # posts to /api/ctb/patch-and-upload, which parses/rewrites a CTB
            # header server-side. Since ELEGOO Jupiter 2 captures are now named
            # ".goo" (v5 GOO bytes, see handle_client()'s SaveFile-request
            # branch), a printer with recommendations configured plus
            # applyRecommendations:true would previously send that .goo file
            # through the CTB-patch endpoint regardless of its real format -
            # either a hard failure or (worse) ScaleX misparsing/corrupting it
            # at CTB-shaped offsets. Gate on the file's own extension instead of
            # trusting the caller's intent alone.
            wants_patch = t.get("applyRecommendations") and has_recommendations(printer)
            is_ctb_patchable = file_path.lower().endswith(".ctb")
            if wants_patch and not is_ctb_patchable:
                logmsg("=== %s: applyRecommendations requested but %s isn't a .ctb file - "
                       "skipping the CTB patch (not applicable to this format), sending as-is ===",
                       pid, os.path.basename(file_path))
            patch = build_recommendation_patch(printer) if (wants_patch and is_ctb_patchable) else {}
            try:
                if patch:
                    status, resp_body = patch_and_upload_single(_get_draft_id(), pid, patch, effective_start_print,
                                                                test_print=test_print)
                    logmsg("=== PATCH+UPLOAD (startPrint=%s, deferred=%s) -> %s: HTTP %d: %s ===",
                           effective_start_print, needs_deferred_start, pid, status, resp_body[:400].decode("utf-8", "replace"))
                else:
                    # Timings already fine for this printer (or no
                    # recommendations to apply) - skip the rewrite, send
                    # the file as-is.
                    status, resp_body = forward_to_scalex(file_path, pid, display_name=name,
                                                          start_print=effective_start_print, test_print=test_print)
                if 200 <= status < 300:
                    try:
                        initial_json = json.loads(resp_body.decode("utf-8", "replace"))
                    except Exception:
                        initial_json = {}
                    upload_id = initial_json.get("uploadId")
                    uploaded_path[0] = initial_json.get("lastUploadedPath")
                    if upload_id:
                        poll_scalex_upload("/api/uploads/%s" % upload_id, name, progress_cb=_cb)
                    elif needs_deferred_start:
                        _register_deferred_start()
                    else:
                        with tracker_lock:
                            tracker[pid]["phase"] = "done"
                            tracker[pid]["percent"] = 100.0
                        _report()
                else:
                    logmsg("=== send-and-start rejected for %s: HTTP %d ===", pid, status)
                    with tracker_lock:
                        tracker[pid]["phase"] = "error"
                        tracker[pid]["percent"] = 100.0
                        # 409 means ScaleX itself found the printer already
                        # busy with something else at the moment it tried
                        # to actually start the transfer - a real, live
                        # conflict, not the same thing as the remainingMemory
                        # pre-check above (confirmed live 2026-08-25: a
                        # printer can pass the memory check and still get
                        # 409'd seconds later because something else is
                        # concurrently using it that slm_chitu_send's own
                        # periodic snapshot never saw). Worth its own
                        # message instead of a generic "Ошибка" so a retry
                        # actually tells you something useful.
                        tracker[pid]["errorReason"] = "conflict" if status == 409 else None
                    _report()
            except Exception as e:
                logmsg("=== send-and-start FAILED for %s (%s) ===", pid, e)
                with tracker_lock:
                    tracker[pid]["phase"] = "error"
                    tracker[pid]["percent"] = 100.0
                _report()

        threads = [threading.Thread(target=_send_one, args=(t,), daemon=True) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        _report()

    threading.Thread(target=_run, daemon=True).start()
