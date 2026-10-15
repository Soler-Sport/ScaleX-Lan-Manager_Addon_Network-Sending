


# ---------------------------------------------------------------------------
# Printer filter/status helpers - ported straight from the old PAGE_HTML's
# JS (isBusy/isOnline/matchesMachine), which itself mirrors ScaleX's own
# isPrinterPrintingStatus() (app.js). Kept as plain functions so the same
# logic could be unit-tested or reused outside the GUI later.
# ---------------------------------------------------------------------------
_BUSY_IDLE_TEXT = ("idle", "stopped", "complete", "completed")


_BUSY_TEXT = ("preparing", "homing", "lifting", "exposing", "printing", "pausing", "paused", "stopping")


def _format_bytes(n):
    if n >= 1024 ** 3:
        return "%.1f ГБ" % (n / 1024 ** 3)
    return "%.0f МБ" % (n / 1024 ** 2)


def printer_memory_fit(printer, file_size):
    """(fits: bool, text: str) for whether `file_size` bytes should fit in
    this printer's currently-reported free space, or None if
    remainingMemory isn't in this printer's data at all (some firmware/
    older printers may not report it - stay silent rather than guess).
    Purely informational/proactive (per user request 2026-08-26, replacing
    the old select-send-fail-retry discovery flow) - send_in_background's
    own pre-check right before actually dispatching is the real, final
    word; this can be a few seconds stale by the time someone clicks
    Send."""
    if file_size is None:
        return None
    remaining = (printer.get("status") or {}).get("remainingMemory")
    try:
        remaining = int(remaining) if remaining is not None else None
    except (TypeError, ValueError):
        remaining = None
    if remaining is None:
        return None
    if remaining >= file_size:
        return True, "Поместится (свободно %s)" % _format_bytes(remaining)
    return False, "Не хватит места (нужно %s, свободно %s)" % (_format_bytes(file_size), _format_bytes(remaining))


def printer_is_uploading(p):
    """True while ScaleX still has an active (non-final) upload job
    targeting this printer - i.e. it's already receiving a file right now,
    from someone else's send or a previous slm_chitu_send batch. printStatus
    alone can still read "idle" for the whole transfer (the printer only
    starts actually printing once the file has fully landed and, if
    autoStart was set, ScaleX tells it to) - printer_is_busy() alone would
    miss this entirely, so it's folded in below rather than requiring a
    separate filter checkbox (per user request 2026-08-25 - same
    "Скрывать занятые" toggle should cover it, ScaleX's own manager
    exposes this exact state on every printer's "upload" field)."""
    u = p.get("upload")
    if not u:
        return False
    return not (u.get("done") or u.get("cancelled"))


def printer_is_busy(p):
    if printer_is_uploading(p):
        return True
    s = p.get("status") or {}
    try:
        current_status = int(s.get("currentStatus") or 0)
    except (TypeError, ValueError):
        current_status = 0
    try:
        print_status = int(s.get("printStatus") or 0)
    except (TypeError, ValueError):
        print_status = 0
    text = str(s.get("printStatusText") or "").lower()
    if current_status == 0 or print_status in (8, 9) or text in _BUSY_IDLE_TEXT:
        return False
    return current_status == 1 or print_status in (1, 2, 3, 4, 5, 6, 7) or text in _BUSY_TEXT


def printer_is_online(p):
    return bool((p.get("status") or {}).get("online") is True)


def printer_matches_machine(p, detected_machine):
    if not detected_machine:
        return True
    model = (p.get("model") or p.get("machineModel") or "").strip()
    if not model:
        return True  # printer has no model info - can't tell, don't hide it
    # Suffix match, not exact/substring: CHITUBOX sometimes glues a couple of
    # stray bytes onto the *front* of the embedded machine name, and this
    # also correctly tells "Saturn 4 Ultra" apart from "Saturn 4 Ultra 16K"
    # (a plain substring check would match both against either file).
    return detected_machine.lower().endswith(model.lower())


def printer_rec_summary(p):
    parts = []
    if p.get("recommendedNormalExposure") not in (None, ""):
        parts.append("обычная %ss" % p["recommendedNormalExposure"])
    if p.get("recommendedBottomExposure") not in (None, ""):
        parts.append("нижняя %ss" % p["recommendedBottomExposure"])
    if p.get("recommendedBottomLayers") not in (None, ""):
        parts.append("%s нижних слоёв" % p["recommendedBottomLayers"])
    return ", ".join(parts)
