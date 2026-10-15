import http.client
import json
import os
import time
import urllib.parse

from . import config
from .logs import logmsg


# ---------------------------------------------------------------------------
# ScaleX API
# ---------------------------------------------------------------------------
def fetch_printers():
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=10)
    try:
        conn.request("GET", "/api/printers")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError("HTTP %d" % resp.status)
        return json.loads(body.decode("utf-8", "replace"))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CTB composition (2026-09-24) - ScaleX's own "состав CTB" warehouse feature
# (PUT /api/warehouse/ctb-mappings, reverse-engineered from its app.js) lets
# an operator attach a list of {component_id, quantity} to a file name, for
# stock tracking once a print finishes. Its own browser-side suggestion logic
# (suggestedCtbCompositionArticles in app.js) only ever matches ONE component,
# by substring-searching the .ctb's own file name - useless for a
# multi-model plate with several different parts on it. ChituHook (and its
# goo_hook.dll-merged successor, C:\ChituHook) hooks CHITUBOX Pro's own save
# path and writes a flat JSON array of every model's original (pre-import)
# filename next to the saved .ctb, same base name - see
# C:\ChituHook\chitu_filelist_hook_pro.c's own header comment. That gives an
# exact per-model list to match against warehouse component codes instead.
# ---------------------------------------------------------------------------
WAREHOUSE_CONTEXTS = ("warehouse", "orders")  # «Виртуальный склад» / «Склад заказов» - ScaleX's X-Warehouse-Context


def fetch_warehouse_components(context="warehouse"):
    """Components of one ScaleX warehouse context. 2026-10-02: ScaleX keeps
    two separate warehouses («Виртуальный склад» = "warehouse", «Склад
    заказов» = "orders", selected per request by the X-Warehouse-Context
    header) with disjoint component sets - Box(17,18) lives only in
    "orders", so reading just the default one left it permanently
    unmatched. The header is only sent for non-default contexts, so the
    default call is unchanged."""
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=10)
    try:
        headers = {} if context == "warehouse" else {"X-Warehouse-Context": context}
        conn.request("GET", "/api/warehouse", headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError("HTTP %d" % resp.status)
        data = json.loads(body.decode("utf-8", "replace"))
        return data.get("components") or []
    finally:
        conn.close()


def fetch_all_warehouse_components():
    """Components of every ScaleX warehouse context, each copy tagged with
    its own "warehouseContext" so a later save goes to the right one. The
    main warehouse must succeed (raises like before); the orders one is
    best-effort - if it fails the plate is still matched against the main
    warehouse, with the failure logged."""
    result = []
    for context in WAREHOUSE_CONTEXTS:
        try:
            comps = fetch_warehouse_components(context)
        except Exception as e:
            if context == "warehouse":
                raise
            logmsg("=== COMPOSITION: failed to fetch %r warehouse components: %s ===", context, e)
            continue
        result.extend(dict(c, warehouseContext=context) for c in comps)
    return result


def save_ctb_composition(file_name, component_quantities, context="warehouse"):
    """PUT /api/warehouse/ctb-mappings - {file_name, component_quantities:
    [{component_id, quantity}]}. This REPLACES whatever composition ScaleX
    already has for this file name, so callers must only call this with a
    genuinely non-empty component_quantities (see PickerWindow's own
    "matched or don't call this at all" guard) - an accidental empty write
    here would silently wipe out a real composition an operator assigned by
    hand through ScaleX's own UI."""
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=15)
    try:
        body = json.dumps({
            "file_name": file_name,
            "component_quantities": [
                {"component_id": cid, "quantity": qty} for cid, qty in component_quantities
            ],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if context != "warehouse":
            headers["X-Warehouse-Context"] = context
        conn.request("PUT", "/api/warehouse/ctb-mappings", body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        if resp.status not in (200, 201, 202):
            raise RuntimeError("HTTP %d: %s" % (resp.status, resp_body.decode("utf-8", "replace")[:300]))
    finally:
        conn.close()


def _progress_from_status(status):
    """Best-effort (percent, message) out of either ScaleX status shape:
    /api/uploads/{id} (flat percent/stage) or /api/bulk-uploads/{id}
    (a "targets" list, one entry per printer, each with its own percent)."""
    targets = status.get("targets")
    if isinstance(targets, list) and targets:
        vals = []
        for t in targets:
            try:
                vals.append(float(t.get("percent") or 0))
            except Exception:
                vals.append(0.0)
        percent = sum(vals) / len(vals)
        states = sorted(set(str(t.get("state") or t.get("stage") or "") for t in targets if (t.get("state") or t.get("stage"))))
        return percent, ", ".join(states)
    if status.get("percent") is not None:
        try:
            return float(status.get("percent")), str(status.get("stage") or status.get("state") or "")
        except Exception:
            pass
    return None, str(status.get("state") or status.get("stage") or "")


def _post_raw_file(path, body_bytes, extra_headers):
    filename_header, data = body_bytes
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=1800)
    try:
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(data)),
            "X-File-Name": filename_header,
        }
        headers.update(extra_headers)
        conn.request("POST", path, body=data, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        return resp.status, resp_body
    finally:
        conn.close()


def forward_to_scalex(file_path, printer_id, display_name=None, start_print=None, test_print=False):
    """Single-printer upload, no CTB patching: POST /api/printers/{id}/files.
    Fast path - ScaleX just streams the file straight to the printer, no
    temporary copy/rewrite involved (that only happens via the CTB
    draft/patch-and-upload flow below, and only when there's an actual
    patch to apply). start_print=None keeps the old SCALEX_START_PRINT
    default; pass True/False to override per call. test_print marks the
    print as «Тестовая - без учёта склада» (ScaleX's own X-Test-Print
    header, same one its upload dialog sets) - only sent when true, so a
    normal send's request is unchanged."""
    if start_print is None:
        start_print = config.SCALEX_START_PRINT
    filename = display_name or os.path.basename(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    headers = {"X-Start-Print": "true" if start_print else "false"}
    if test_print:
        headers["X-Test-Print"] = "true"
    status, resp_body = _post_raw_file(
        "/api/printers/%s/files" % printer_id,
        (urllib.parse.quote(filename), data),
        headers,
    )
    logmsg("=== FORWARD TO SCALEX (single, unpatched): %s -> HTTP %d: %s ===",
           filename, status, resp_body[:500].decode("utf-8", "replace"))
    return status, resp_body


# NOT USED by send_in_background any more (see its docstring) - ScaleX's
# own bulk-uploads/from-draft endpoint is marked "experimental" in its own
# API response and was observed live (2026-08-20) starting a real print
# despite the request never asking it to. Left defined only in case ScaleX
# fixes/documents that endpoint's actual queue-only contract later; do not
# wire this back into the live send path without re-verifying that first.
def forward_to_scalex_bulk(file_path, printer_ids, display_name=None):
    """Multi-printer upload, no CTB patching: POST /api/bulk-uploads with
    X-Printer-Ids. UNUSED - see module-level warning above this function."""
    filename = display_name or os.path.basename(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    status, resp_body = _post_raw_file(
        "/api/bulk-uploads",
        (urllib.parse.quote(filename), data),
        {"X-Printer-Ids": urllib.parse.quote(json.dumps(printer_ids))},
    )
    logmsg("=== FORWARD TO SCALEX (bulk, %d printers, unpatched): %s -> HTTP %d: %s ===",
           len(printer_ids), filename, status, resp_body[:500].decode("utf-8", "replace"))
    return status, resp_body


def ctb_params(file_path, display_name=None):
    """POST /api/ctb/params: reads the CTB header (exposure/layer params)
    and stashes the file server-side under a draftId, so it doesn't need
    re-uploading once per target printer. Confirmed live 2026-08-19.
    display_name (if given) is what ScaleX will call the file downstream -
    this is the "rename before sending" hook, same idea as ChituManager's
    own editable filename field."""
    filename = display_name or os.path.basename(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    status, resp_body = _post_raw_file("/api/ctb/params", (urllib.parse.quote(filename), data), {})
    if status != 200:
        raise RuntimeError("ctb/params HTTP %d: %s" % (status, resp_body[:300]))
    return json.loads(resp_body.decode("utf-8", "replace"))


def create_bulk_from_draft(draft_id, targets):
    """POST /api/bulk-uploads/from-draft {draftId, targets}. targets is a
    list of {"printerId": str, "applyRecommendations": bool} - each printer
    with applyRecommendations:true gets ITS OWN recommended normal/bottom
    exposure + bottom layer count patched into the CTB header before
    upload (confirmed live 2026-08-19: server rewrites the file and mode
    comes back "recommended" with the actual patch values applied).
    applyRecommendations:true on a printer with no recommendations
    configured is rejected with a clear 400 - caller should only set it for
    printers that actually have recommendedNormalExposure/etc. populated."""
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=1800)
    try:
        body = json.dumps({"draftId": draft_id, "targets": targets}).encode("utf-8")
        conn.request("POST", "/api/bulk-uploads/from-draft", body=body,
                      headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp_body = resp.read()
        return resp.status, resp_body
    finally:
        conn.close()


def has_recommendations(printer):
    return (
        printer.get("recommendedNormalExposure") not in (None, "")
        or printer.get("recommendedBottomExposure") not in (None, "")
        or printer.get("recommendedBottomLayers") not in (None, "")
    )


def build_recommendation_patch(printer):
    """The explicit-values twin of applyRecommendations:true - same fields
    ScaleX's own upload modal sends to /api/ctb/patch-and-upload (its
    "apply recommendations" checkbox literally copies these three values in
    as numbers, confirmed in app.js)."""
    patch = {}
    if printer.get("recommendedNormalExposure") not in (None, ""):
        patch["normalExposure"] = printer["recommendedNormalExposure"]
    if printer.get("recommendedBottomExposure") not in (None, ""):
        patch["bottomExposure"] = printer["recommendedBottomExposure"]
    if printer.get("recommendedBottomLayers") not in (None, ""):
        patch["bottomLayers"] = printer["recommendedBottomLayers"]
    return patch


def patch_and_upload_single(draft_id, printer_id, patch, auto_start, test_print=False):
    """POST /api/ctb/patch-and-upload {printerId, draftId, patch, autoStart}.
    Single-printer only - it's the only ScaleX endpoint that actually starts
    a print (X-Start-Print/autoStart isn't honoured by the bulk endpoints at
    all, confirmed in app.js), so a multi-printer "start print" send loops
    this call once per target printer. testPrint (ScaleX's own field, see
    forward_to_scalex) is only included when true."""
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=1800)
    try:
        payload = {
            "printerId": printer_id, "draftId": draft_id,
            "patch": patch, "autoStart": bool(auto_start),
        }
        if test_print:
            payload["testPrint"] = True
        body = json.dumps(payload).encode("utf-8")
        conn.request("POST", "/api/ctb/patch-and-upload", body=body,
                      headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp_body = resp.read()
        return resp.status, resp_body
    finally:
        conn.close()


def start_stored_file(printer_id, path, queue_if_not_prepared):
    """POST /api/printers/{id}/stored-files/start {path, queueIfNotPrepared} -
    ScaleX's own two-step mechanism (confirmed via its own app.js,
    2026-08-27) for starting a file that's already been uploaded to a
    printer's local storage. With queueIfNotPrepared=True, ScaleX accepts
    the request even if the printer isn't marked operatorPrepared yet and
    holds the actual print start until an operator confirms it - this is
    what "ожидание подготовки" in ScaleX's own UI actually is, distinct
    from either starting blind or refusing outright. Without it (False),
    an unprepared printer makes this endpoint fail with
    {"error":"printer_not_prepared"} (non-2xx) - same shape send_in_background
    checks for below."""
    conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=30)
    try:
        body = json.dumps({"path": path, "queueIfNotPrepared": bool(queue_if_not_prepared)}).encode("utf-8")
        conn.request("POST", "/api/printers/%s/stored-files/start" % urllib.parse.quote(str(printer_id), safe=""),
                      body=body, headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp_body = resp.read()
        return resp.status, resp_body
    finally:
        conn.close()


def forward_to_scalex_with_recommendations(file_path, targets, display_name=None):
    """Preferred path: targets = [{"printerId": id, "applyRecommendations": bool}, ...].
    Uses the CTB-draft flow so each printer marked applyRecommendations
    gets its own exposure settings patched in before upload."""
    filename = display_name or os.path.basename(file_path)
    draft = ctb_params(file_path, display_name=filename)
    draft_id = draft.get("draftId")
    logmsg("=== CTB DRAFT: %s draftId=%s parameters=%s ===",
           filename, draft_id, json.dumps(draft.get("parameters"))[:300])

    status, resp_body = create_bulk_from_draft(draft_id, targets)
    logmsg("=== FORWARD TO SCALEX (from-draft, %d target(s)): %s -> HTTP %d: %s ===",
           len(targets), filename, status, resp_body[:600].decode("utf-8", "replace"))
    return status, resp_body


def poll_scalex_upload(path, filename, timeout_sec=1800, interval_sec=2.0, progress_cb=None):
    """Generic poller for GET {path} - works for both /api/uploads/{id} and
    /api/bulk-uploads/{id} as long as the response has a "done" bool.
    progress_cb, if given, is called on every tick as
    progress_cb(is_terminal, is_error, job_percent_0_100_or_None, message,
    raw_status_dict) - lets a caller polling several printers concurrently
    (see send_in_background) aggregate them itself and report to its own
    GUI. raw_status_dict is the full parsed response, mainly so a caller
    can pull fields the flat (percent, message) summary doesn't carry -
    e.g. lastUploadedPath, which patch-and-upload's own initial 202
    response doesn't include at all (confirmed live 2026-08-27) but the
    polled status does once the upload actually starts moving."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        conn = None
        try:
            # Constructing HTTPConnection itself doesn't touch the network
            # (no socket opens until the first request), so this has never
            # been observed failing in practice - but it's still a real
            # code path, and moving it outside this try (as an earlier
            # version did) meant any failure here would propagate straight
            # out of poll_scalex_upload uncaught, crashing whatever thread
            # is polling instead of reporting it via progress_cb like every
            # other failure mode here does. Caught during test-writing
            # 2026-08-31, not live - fixed defensively either way.
            conn = http.client.HTTPConnection(config.SCALEX_HOST, config.SCALEX_PORT, timeout=15)
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
        except Exception as e:
            logmsg("=== upload status check failed for %s (%s): %s ===", filename, path, e)
            if progress_cb:
                progress_cb(True, True, None, "Не удалось получить статус: %s" % e, {})
            return
        finally:
            if conn is not None:
                conn.close()
        try:
            status = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            logmsg("=== upload status for %s: non-JSON response, giving up polling ===", filename)
            if progress_cb:
                progress_cb(True, False, 100.0, "", {})
            return

        # Two shapes seen live: /api/uploads/{id} has an explicit "done"
        # bool; /api/bulk-uploads/{id} instead has "state" reaching one of
        # these terminal values (confirmed via a real test upload).
        is_terminal = status.get("done") is True or status.get("state") in (
            "completed", "failed", "error", "cancelled",
        )
        is_error = status.get("state") in ("failed", "error", "cancelled")
        job_percent, message = _progress_from_status(status)
        if job_percent is None:
            job_percent = 100.0 if (is_terminal and not is_error) else None
        if progress_cb:
            progress_cb(is_terminal, is_error, job_percent, message, status)
        if is_terminal:
            logmsg("=== UPLOAD STATUS %s: %s ===", filename, json.dumps(status)[:500])
            return
        time.sleep(interval_sec)
    logmsg("=== upload status poll timed out for %s ===", filename)
    if progress_cb:
        progress_cb(True, True, None, "Тайм-аут ожидания статуса", {})
