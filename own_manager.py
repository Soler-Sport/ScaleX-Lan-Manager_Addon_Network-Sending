"""
own_manager.py - forwards every file CHITUBOX sends over "Network Sending"
to one or more printers on your own ScaleX LAN Manager farm. A real web
page (own_manager's own local HTTP server, styled with ScaleX's own
styles.css so it looks like part of the same app) pops up in the browser
for each captured file, letting you rename it, pick printers (checkboxes),
and apply each printer's own recommended exposure settings.

Run: python own_manager.py   (keep the console window open)
Log: C:\\own_manager\\own_manager.log

============================================================================
SESSION NOTES
============================================================================
Three architectures for getting the file out of CHITUBOX were tried; see
git history for the two abandoned ones: (1) full ChituManager replacement
via QSharedMemory hijack - got surprisingly far, including a real login
bypass and the whole farm rendering, but the printer card's
WebSocket-connect trigger never fired despite matching the decompiled
source; (2) let CHITUBOX launch the real ChituManager normally and watch
the sliced file it drops under ChituManager's own AppData - worked, but
still required clicking through ChituManager's own login/printer-select/
Send UI every time.

This file uses the one that actually works end to end with zero
ChituManager involvement: own_manager hijacks the same QSharedMemory
segment CHITUBOX uses to discover "the manager" (create_shared_memory),
so CHITUBOX connects straight to own_manager's own TCP listener instead of
launching ChituManager at all. CHITUBOX itself (not ChituManager) natively
understands a {"MsgType":"SaveFile","FilePath":"<path>"} request and will
either copy its already-sliced internal file or run a real slice job and
then write exactly that path (confirmed via Ghidra decompile of CHITUBOX
Pro.exe's own ChituManager::saveSliceFile / ChituManager::saveSlicerFileOver,
2026-08-19) - own_manager asks for this the moment CHITUBOX says it's ready
(its "LoadWindow" ping) and, once the file lands, opens the picker page.

The picker UI first used tkinter (a native popup); this version replaces
that with a small page served by own_manager's own HTTP server, reusing
ScaleX's real stylesheet (http://<scalex host>/styles.css) and its own
CSS class names (.bulk-printer-option etc.) so it looks like a real part
of the same app instead of a generic desktop dialog.

============================================================================
ScaleX upload contracts (reverse-engineered from its own app.js + live
tests against the real "Test" printer, 2026-08-19/20)
============================================================================
send_in_background ONLY ever uses the single-printer endpoints below now
(dispatched once per selected printer, in parallel). The bulk/from-draft
endpoints are documented here for reference and still defined in code
(forward_to_scalex_bulk/create_bulk_from_draft/
forward_to_scalex_with_recommendations) but are NOT called - ScaleX's own
API response marks that path "experimental", and it was observed live
(2026-08-20) starting a real print on a printer even though the request
never asked it to (X-Start-Print/autoStart isn't even a field this
endpoint accepts) - its "queue only" behaviour cannot be trusted. Don't
re-wire it into the live send path without re-verifying that first.

Single printer, no CTB patching (the default when a printer's exposure
doesn't need changing):
    POST /api/printers/{printer_id}/files
    X-File-Name: <urlencoded filename>
    X-Start-Print: true|false   <- confirmed accurate for this endpoint
    <raw file bytes as body>
    -> 202 {"uploadId": ...}; poll GET /api/uploads/{uploadId}

Single printer with CTB patching (recommended exposure applied):
    1. POST /api/ctb/params  X-File-Name + raw body -> {draftId, parameters}
       (fetched once, lazily, only if some target actually needs a patch)
    2. POST /api/ctb/patch-and-upload  {printerId, draftId, patch, autoStart}
       -> makes a temporary rewritten copy of the file server-side (~1min)
    3. poll GET /api/uploads/{uploadId}

Bulk endpoints (UNUSED, see warning above):
    POST /api/bulk-uploads  X-File-Name + X-Printer-Ids + raw body
    POST /api/bulk-uploads/from-draft  {draftId, targets:[{printerId, applyRecommendations}]}
    poll GET /api/bulk-uploads/{id}
applyRecommendations:true on a printer with no recommendations configured
is rejected by ScaleX with a clear 400 - only set it for printers that
actually have recommendedNormalExposure/etc. populated (has_recommendations
below).
"""
import os
import re
import sys
import time
import json
import uuid
import base64
import struct
import ctypes
import socket
import shutil
import datetime
import threading
import http.client
import http.server
import urllib.parse
import webview
from ctypes import wintypes

try:
    from Crypto.Cipher import AES  # pip install pycryptodome - see extract_ctb_machine_name
except ImportError:
    AES = None

ROOT_DIR = r"C:\own_manager"
RECEIVED_DIR = os.path.join(ROOT_DIR, "received")  # local backup copy, always kept
LOG_PATH = os.path.join(ROOT_DIR, "own_manager.log")

# Confirmed by a live capture on 2026-08-19: CHITUBOX writes the actual
# sliced file here the instant a real "Send by network" completes - one
# timestamped subfolder per job, a random-hex-named slice file inside.
SLICER_WATCH_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser(r"~\AppData\Local")),
    "ChituManager", "cbdsa-chitubox-network", "SlicerFile",
)
SLICE_EXTENSIONS = (".ctb", ".goo", ".cbddlp", ".pwmx")
POLL_INTERVAL_SEC = 2.0

PENDING_DIR = os.path.join(ROOT_DIR, "pending")  # files requested straight from CHITUBOX over TCP

# ---------------------------------------------------------------------------
# CTB header sniffing - so the picker can show/filter to only the printers a
# file was actually sliced for.
#
# Primary method: parse the real "Chitubox CTB (Encrypted)" structure
# (magic 0x12FD0107) - a 48-byte unencrypted FileHeader points at a 288-byte
# SlicerSettings block, AES-256-CBC-encrypted with a fixed key/IV that's
# baked into the format itself (obfuscation, not a real secret - the same
# key/IV work for every file of this format). That block has
# MachineNameOffset/MachineNameSize fields pointing at the exact plain-ASCII
# machine name elsewhere in the file - byte-exact, no guessing. Courtesy of
# a ready-made parser the user already had (ctb_header_tool.py) confirmed
# against every real captured file on 2026-08-20.
#
# Fallback: a plain text scan for CHITUBOX's copyright notice, which the
# machine name sits right before - used if the precise parse fails (e.g. a
# different/newer CTB version, or pycryptodome isn't installed). Offset of
# that anchor isn't fixed/near the start (seen anywhere from ~6KB to ~5MB
# in), so it scans forward in chunks rather than assuming a small header.
# ---------------------------------------------------------------------------
CTB_ENCRYPTED_MAGIC = 0x12FD0107
_CTB_AES_KEY_B64 = "hQ36XB6yTk+zO02ysyiowt8yC1buK+nbLWyfY40EXoU="
_CTB_AES_IV_B64 = "Wld+ampndVJecmVjYH5cWQ=="
_CTB_XOR_PASSPHRASE = "UVtools"  # format constant, not a real secret

# Transcribed verbatim (name, struct-type) from ctb_header_tool.py's
# FILE_HEADER_FIELDS/SETTINGS_FIELDS - kept as explicit (name, type) pairs
# rather than a hand-flattened format string, so it's easy to check against
# the source instead of trusting a manual character count.
_CTB_HEADER_FIELDS = [
    ("Magic", "I"), ("SettingsSize", "I"), ("SettingsOffset", "I"), ("Unknown1", "I"),
    ("Version", "I"), ("SignatureSize", "I"), ("SignatureOffset", "I"), ("Unknown", "I"),
    ("Unknown4", "H"), ("Unknown5", "H"), ("Unknown6", "I"), ("Unknown7", "I"), ("Unknown8", "I"),
]
_CTB_SETTINGS_FIELDS = [
    ("ChecksumValue", "Q"), ("LayerPointersOffset", "I"), ("DisplayWidth", "f"),
    ("DisplayHeight", "f"), ("MachineZ", "f"), ("Unknown1", "I"), ("Unknown2", "I"),
    ("TotalHeightMillimeter", "f"), ("LayerHeight", "f"), ("ExposureTime", "f"),
    ("BottomExposureTime", "f"), ("LightOffDelay", "f"), ("BottomLayerCount", "I"),
    ("ResolutionX", "I"), ("ResolutionY", "I"), ("LayerCount", "I"),
    ("LargePreviewOffset", "I"), ("SmallPreviewOffset", "I"), ("PrintTime", "I"),
    ("ProjectorType", "I"), ("BottomLiftHeight", "f"), ("BottomLiftSpeed", "f"),
    ("LiftHeight", "f"), ("LiftSpeed", "f"), ("RetractSpeed", "f"),
    ("MaterialMilliliters", "f"), ("MaterialGrams", "f"), ("MaterialCost", "f"),
    ("BottomLightOffDelay", "f"), ("Unknown3", "I"), ("LightPWM", "H"), ("BottomLightPWM", "H"),
    ("LayerXorKey", "I"), ("BottomLiftHeight2", "f"), ("BottomLiftSpeed2", "f"),
    ("LiftHeight2", "f"), ("LiftSpeed2", "f"), ("RetractHeight2", "f"), ("RetractSpeed2", "f"),
    ("RestTimeAfterLift", "f"), ("MachineNameOffset", "I"), ("MachineNameSize", "I"),
    ("AntiAliasFlag", "B"), ("Padding", "H"), ("PerLayerSettings", "B"),
    ("ModifiedTimestampMinutes", "I"), ("AntiAliasLevel", "I"), ("RestTimeAfterRetract", "f"),
    ("RestTimeAfterLift2", "f"), ("TransitionLayerCount", "I"), ("BottomRetractSpeed", "f"),
    ("BottomRetractSpeed2", "f"), ("Padding1", "I"), ("Four1", "f"), ("Padding2", "I"),
    ("Four2", "f"), ("RestTimeAfterRetract2", "f"), ("RestTimeAfterLift3", "f"),
    ("RestTimeBeforeLift", "f"), ("BottomRetractHeight2", "f"), ("Unknown6", "I"),
    ("Unknown7", "I"), ("Unknown8", "I"), ("LastLayerIndex", "I"), ("Padding3", "I"),
    ("Padding4", "I"), ("Padding5", "I"), ("Padding6", "I"), ("DisclaimerOffset", "I"),
    ("DisclaimerSize", "I"), ("Padding7", "I"), ("ResinParametersAddress", "I"),
    ("Padding8", "I"), ("Padding9", "I"),
]
_CTB_HEADER_FMT = "<" + "".join(t for _, t in _CTB_HEADER_FIELDS)
_CTB_SETTINGS_FMT = "<" + "".join(t for _, t in _CTB_SETTINGS_FIELDS)
_CTB_SETTINGS_INDEX = {name: i for i, (name, _) in enumerate(_CTB_SETTINGS_FIELDS)}


def _ctb_xor(data, key):
    kb = key.encode("utf-8")
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def _extract_ctb_machine_name_precise(file_path):
    """Byte-exact via the real struct - returns None (never raises) if this
    isn't a "CTB Encrypted" file, the struct doesn't line up, or
    pycryptodome isn't installed, so the caller can fall back cleanly."""
    if AES is None:
        return None
    try:
        with open(file_path, "rb") as f:
            header_size = struct.calcsize(_CTB_HEADER_FMT)
            header_raw = f.read(header_size)
            if len(header_raw) < header_size:
                return None
            header = dict(zip((n for n, _ in _CTB_HEADER_FIELDS), struct.unpack(_CTB_HEADER_FMT, header_raw)))
            if header["Magic"] != CTB_ENCRYPTED_MAGIC:
                return None

            settings_size = struct.calcsize(_CTB_SETTINGS_FMT)
            if settings_size != header["SettingsSize"]:
                return None  # different format version than this struct - don't guess, fall back

            f.seek(header["SettingsOffset"])
            encrypted = f.read(settings_size)
            if len(encrypted) != settings_size:
                return None

            key = _ctb_xor(base64.b64decode(_CTB_AES_KEY_B64), _CTB_XOR_PASSPHRASE)
            iv = _ctb_xor(base64.b64decode(_CTB_AES_IV_B64), _CTB_XOR_PASSPHRASE)
            decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)

            settings_vals = struct.unpack(_CTB_SETTINGS_FMT, decrypted)
            name_offset = settings_vals[_CTB_SETTINGS_INDEX["MachineNameOffset"]]
            name_size = settings_vals[_CTB_SETTINGS_INDEX["MachineNameSize"]]
            if not (0 < name_size <= 128):
                return None

            f.seek(name_offset)
            name_raw = f.read(name_size)
            if len(name_raw) != name_size:
                return None
            return name_raw.decode("ascii", "replace").strip() or None
    except Exception as e:
        logmsg("=== _extract_ctb_machine_name_precise FAILED for %s (%s) ===", file_path, e)
        return None


CTB_MACHINE_NAME_ANCHOR = b"Layout and record format for the ctb and cbddlp file types"
CTB_SCAN_CHUNK = 4 * 1024 * 1024
CTB_SCAN_MAX = 24 * 1024 * 1024  # give up past this - picker just shows every printer, same as before


def _extract_ctb_machine_name_fallback(file_path):
    """Text-scan fallback - see module notes above. A couple of stray
    binary bytes sometimes end up glued to the *front* of the captured
    string (harmless noise from whatever field precedes it - never the
    back), trimmed off by starting at the first run that actually looks
    like the start of a real word."""
    try:
        with open(file_path, "rb") as f:
            prev_tail = b""
            scanned = 0
            while scanned < CTB_SCAN_MAX:
                chunk = f.read(CTB_SCAN_CHUNK)
                if not chunk:
                    break
                buf = prev_tail + chunk
                idx = buf.find(CTB_MACHINE_NAME_ANCHOR)
                if idx >= 0:
                    before = buf[max(0, idx - 64):idx]
                    m = re.search(rb"[ -~]+$", before)
                    if not m:
                        return None
                    raw = m.group(0)
                    start = re.search(rb"[A-Z][A-Za-z0-9]{2,}", raw)
                    clean = raw[start.start():] if start else raw
                    return clean.decode("ascii", "replace").strip()
                prev_tail = buf[-len(CTB_MACHINE_NAME_ANCHOR):]
                scanned += len(chunk)
    except Exception as e:
        logmsg("=== _extract_ctb_machine_name_fallback FAILED for %s (%s) ===", file_path, e)
    return None


def extract_ctb_machine_name(file_path):
    """Best-effort: returns the CTB's embedded target-machine name (e.g.
    "ELEGOO Saturn 4 Ultra 16K"), or None if it can't be determined."""
    name = _extract_ctb_machine_name_precise(file_path)
    if name:
        return name
    return _extract_ctb_machine_name_fallback(file_path)

# ---------------------------------------------------------------------------
# CHITUBOX discovery hijack (QSharedMemory) - so CHITUBOX connects to us
# instead of launching ChituManager. This exact name was found via Ghidra
# decompile + a breakpoint on OpenFileMappingW (see README.md).
# ---------------------------------------------------------------------------
SHM_NAME = "qipc_sharedmemory_ServerPort07a1a6dcfadd97d64f9f7f13063e6345d8b33ce8"
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
PAGE_READWRITE = 0x04
FILE_MAP_WRITE = 0x0002
FILE_MAP_READ = 0x0004
ERROR_ALREADY_EXISTS = 183

kernel32.CreateFileMappingW.restype = wintypes.HANDLE
kernel32.CreateFileMappingW.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
]
kernel32.MapViewOfFile.restype = wintypes.LPVOID
kernel32.MapViewOfFile.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t,
]

_shm_handle = None  # kept alive for the process lifetime, intentionally never closed
_shm_view = None


def create_shared_memory(name, port_str):
    global _shm_handle, _shm_view
    h = kernel32.CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, 4096, name)
    if not h:
        logmsg("CreateFileMappingW(%s) FAILED, err=%d", name, ctypes.get_last_error())
        return False
    err = ctypes.get_last_error()
    view = kernel32.MapViewOfFile(h, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 4096)
    if not view:
        logmsg("MapViewOfFile(%s) FAILED, err=%d", name, ctypes.get_last_error())
        kernel32.CloseHandle(h)
        return False
    data = port_str.encode("ascii") + b"\x00"
    ctypes.memmove(view, data, len(data))
    logmsg("CreateFileMappingW(%s) OK (alreadyExisted=%s), wrote \"%s\"",
           name, "yes" if err == ERROR_ALREADY_EXISTS else "no", port_str)
    _shm_handle, _shm_view = h, view
    return True


user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.FindWindowW.restype = wintypes.HWND
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, wintypes.LPDWORD]
user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
user32.BringWindowToTop.argtypes = [wintypes.HWND]
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
SW_RESTORE = 9


def _bring_window_to_front(title, timeout=3.0):
    """pywebview windows don't reliably grab focus on their own when a new
    one is created while some other app is in the foreground (e.g.
    CHITUBOX) - find it by its exact title (unique per capture, includes
    the filename) once it's actually mapped, and force it forward. Plain
    SetForegroundWindow silently no-ops here (own_manager is a background
    process with no recent input focus of its own - confirmed live,
    2026-08-20: the call succeeded but the window never actually came
    forward) - Windows only allows it unconditionally for a thread that
    already owns the foreground, so this borrows that via
    AttachThreadInput first (the standard workaround for exactly this)."""
    deadline = time.monotonic() + timeout
    hwnd = None
    while time.monotonic() < deadline:
        hwnd = user32.FindWindowW(None, title)
        if hwnd:
            break
        time.sleep(0.05)
    if not hwnd:
        logmsg("=== _bring_window_to_front: window %r never appeared ===", title)
        return

    # Standard workaround: borrow the current foreground thread's input
    # state onto this thread so Windows lets it call SetForegroundWindow
    # unconditionally, then drop it again.
    fg_hwnd = user32.GetForegroundWindow()
    fg_thread = user32.GetWindowThreadProcessId(fg_hwnd, None)
    current_thread = kernel32.GetCurrentThreadId()

    attached = False
    if fg_thread and fg_thread != current_thread:
        attached = bool(user32.AttachThreadInput(current_thread, fg_thread, True))
    try:
        user32.ShowWindow(hwnd, SW_RESTORE)
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(current_thread, fg_thread, False)


class PickerAPI:
    """Exposed to the picker page's JS as window.pywebview.api.* - lets the
    page ask own_manager to close its own window once a send is done,
    without needing an address bar's tab-close control (there isn't one)."""
    def __init__(self):
        self.window = None

    def close(self):
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception as e:
                logmsg("=== PickerAPI.close FAILED: %s ===", e)


_window_counter = 0
_window_counter_lock = threading.Lock()

# item_id -> unique window title, for the polling cleanup below. Tried
# doing this event-driven via pywebview's win.events.closed instead - that
# reliably froze the entire app (HTTP server included, window turned
# unresponsive) the moment it was registered right after create_window(),
# reproduced live 2026-08-20. Plain polling avoids pywebview's event API
# and reuses the same FindWindowW mechanism _bring_window_to_front already
# uses safely.
_pending_windows = {}
_pending_windows_lock = threading.Lock()


def _pending_cleanup_loop():
    """Runs forever: drops a PENDING entry once its picker window is gone
    (closed via the X button or our own "Закрыть окно" - either way,
    /api/send already popped it if it was actually sent) - see
    _pending_windows comment above for why this is polling, not events."""
    while True:
        time.sleep(10)
        with _pending_windows_lock:
            items = list(_pending_windows.items())
        for item_id, title in items:
            if user32.FindWindowW(None, title):
                continue  # still open
            with _pending_windows_lock:
                _pending_windows.pop(item_id, None)
            with PENDING_LOCK:
                item = PENDING.pop(item_id, None)
            if item:
                logmsg("=== picker window closed without sending, dropped pending entry for %s ===", item["filename"])


def open_app_window(title, url, item_id=None):
    """Open a real native WebView2 window (pywebview, backed by the Edge
    WebView2 runtime) instead of a Chrome/Edge "--app" browser window - no
    address bar to strip, no generic browser favicon in the titlebar, just
    the app's own title text. pywebview requires at least one window to
    exist before webview.start() is ever called (main() creates a hidden
    1x1 sentinel for that), but once it's running, new windows can be
    created from any thread - which is exactly what this does, once per
    captured file."""
    global _window_counter
    with _window_counter_lock:
        _window_counter += 1
        n = _window_counter
    # _bring_window_to_front finds the window by exact title via
    # FindWindowW - two captures of a same-named file (e.g. resending the
    # same part) would otherwise share one title, and it could grab the
    # already-open older window instead of the new one. A handful of
    # zero-width spaces make each window's title unique without changing
    # what's actually visible in the titlebar.
    unique_title = title + (chr(0x200B) * n)
    try:
        api = PickerAPI()
        win = webview.create_window(
            unique_title, url, js_api=api,
            width=880, height=907, min_size=(560, 480), resizable=True,
        )
        api.window = win
        if item_id:
            with _pending_windows_lock:
                _pending_windows[item_id] = unique_title
        threading.Thread(target=_bring_window_to_front, args=(unique_title,), daemon=True).start()
    except Exception as e:
        logmsg("=== open_app_window: webview.create_window failed (%s), falling back to os.startfile ===", e)
        os.startfile(url)

# --- Your own manager (ScaleX LAN Manager, FastAPI/uvicorn) ---
SCALEX_HOST = "192.168.0.118"
SCALEX_PORT = 8082
SCALEX_START_PRINT = False  # queue the transfer only, never auto-start a print

os.makedirs(ROOT_DIR, exist_ok=True)
_log_lock = threading.Lock()
_logf = open(LOG_PATH, "a", encoding="utf-8", newline="")


def logmsg(fmt, *args):
    line = fmt % args if args else fmt
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with _log_lock:
        _logf.write("[%s] %s\r\n" % (ts, line))
        _logf.flush()
    print("[%s] %s" % (ts, line))


# ---------------------------------------------------------------------------
# ScaleX API
# ---------------------------------------------------------------------------
def fetch_printers():
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=10)
    try:
        conn.request("GET", "/api/printers")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError("HTTP %d" % resp.status)
        return json.loads(body.decode("utf-8", "replace"))
    finally:
        conn.close()


SEND_STATUS = {}  # item_id -> {"phase": ..., "percent": ..., "message": ...} - for the picker's progress bar
SEND_STATUS_LOCK = threading.Lock()


def _set_send_status(item_id, phase, percent=None, message="", targets=None):
    """targets (optional): [{"printerId", "label", "phase", "percent"}, ...]
    - lets the picker page draw one progress bar per printer instead of a
    single generic one. If this call doesn't carry a targets list, the
    previously published one (if any) is kept, so callers that only update
    the overall phase/percent don't have to also resend it every time."""
    if not item_id:
        return
    with SEND_STATUS_LOCK:
        entry = {"phase": phase, "percent": percent, "message": message}
        if targets is not None:
            entry["targets"] = targets
        else:
            prev = SEND_STATUS.get(item_id)
            if prev and "targets" in prev:
                entry["targets"] = prev["targets"]
        SEND_STATUS[item_id] = entry


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
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=1800)
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


def forward_to_scalex(file_path, printer_id, display_name=None, start_print=None):
    """Single-printer upload, no CTB patching: POST /api/printers/{id}/files.
    Fast path - ScaleX just streams the file straight to the printer, no
    temporary copy/rewrite involved (that only happens via the CTB
    draft/patch-and-upload flow below, and only when there's an actual
    patch to apply). start_print=None keeps the old SCALEX_START_PRINT
    default; pass True/False to override per call."""
    if start_print is None:
        start_print = SCALEX_START_PRINT
    filename = display_name or os.path.basename(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    status, resp_body = _post_raw_file(
        "/api/printers/%s/files" % printer_id,
        (urllib.parse.quote(filename), data),
        {"X-Start-Print": "true" if start_print else "false"},
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
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=1800)
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


def patch_and_upload_single(draft_id, printer_id, patch, auto_start):
    """POST /api/ctb/patch-and-upload {printerId, draftId, patch, autoStart}.
    Single-printer only - it's the only ScaleX endpoint that actually starts
    a print (X-Start-Print/autoStart isn't honoured by the bulk endpoints at
    all, confirmed in app.js), so a multi-printer "start print" send loops
    this call once per target printer."""
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=1800)
    try:
        body = json.dumps({
            "printerId": printer_id, "draftId": draft_id,
            "patch": patch, "autoStart": bool(auto_start),
        }).encode("utf-8")
        conn.request("POST", "/api/ctb/patch-and-upload", body=body,
                      headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
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


def _bulk_targets_to_picker_targets(status, printers_by_id):
    """ScaleX's /api/bulk-uploads/{id} status has its own "targets" list,
    one entry per printer, each with its own state/percent (confirmed
    live). Reshape that into what the picker page's per-printer progress
    bars expect."""
    raw = status.get("targets")
    if not isinstance(raw, list) or printers_by_id is None:
        return None
    out = []
    for t in raw:
        pid = t.get("printerId")
        printer = printers_by_id.get(str(pid), {})
        label = printer.get("displayName") or printer.get("name") or str(pid)
        state = str(t.get("state") or t.get("stage") or "")
        phase = "error" if state in ("error", "cancelled") else ("done" if state == "completed" else "sending")
        try:
            percent = float(t.get("percent")) if t.get("percent") is not None else None
        except Exception:
            percent = None
        out.append({"printerId": pid, "label": label, "phase": phase, "percent": percent})
    return out


def poll_scalex_upload(path, filename, timeout_sec=1800, interval_sec=2.0, item_id=None,
                        percent_base=0.0, percent_span=100.0, progress_cb=None, printers_by_id=None):
    """Generic poller for GET {path} - works for both /api/uploads/{id} and
    /api/bulk-uploads/{id} as long as the response has a "done" bool.
    If item_id is given, also feeds the picker page's progress bar via
    SEND_STATUS directly - percent_base/percent_span let a caller looping
    over several printers *sequentially* map this one job's 0-100% onto its
    own slice of the overall bar. printers_by_id (optional) lets it also
    publish a per-printer breakdown for /api/bulk-uploads/{id} jobs (see
    _bulk_targets_to_picker_targets).
    If progress_cb is given instead (or as well), it's called on every tick
    as progress_cb(is_terminal, is_error, job_percent_0_100_or_None,
    message) - lets a caller polling several printers *concurrently*
    aggregate them itself instead of fighting over one SEND_STATUS entry."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=15)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
        except Exception as e:
            logmsg("=== upload status check failed for %s (%s): %s ===", filename, path, e)
            if item_id:
                _set_send_status(item_id, "error", None, "Не удалось получить статус: %s" % e)
            if progress_cb:
                progress_cb(True, True, None, "Не удалось получить статус: %s" % e)
            return
        finally:
            conn.close()
        try:
            status = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            logmsg("=== upload status for %s: non-JSON response, giving up polling ===", filename)
            if item_id:
                _set_send_status(item_id, "done", 100, "")
            if progress_cb:
                progress_cb(True, False, 100.0, "")
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
        if item_id:
            overall = None if job_percent is None else percent_base + (job_percent / 100.0) * percent_span
            targets_out = _bulk_targets_to_picker_targets(status, printers_by_id)
            _set_send_status(item_id, "error" if is_error else ("done" if is_terminal else "sending"),
                              overall, message, targets=targets_out)
        if progress_cb:
            progress_cb(is_terminal, is_error, job_percent, message)
        if is_terminal:
            logmsg("=== UPLOAD STATUS %s: %s ===", filename, json.dumps(status)[:500])
            return
        time.sleep(interval_sec)
    logmsg("=== upload status poll timed out for %s ===", filename)
    if item_id:
        _set_send_status(item_id, "error", None, "Тайм-аут ожидания статуса")
    if progress_cb:
        progress_cb(True, True, None, "Тайм-аут ожидания статуса")


def send_in_background(file_path, targets, display_name=None, start_print=False, item_id=None):
    """targets: list of {"printerId": id, "applyRecommendations": bool}.
    display_name: filename to present to ScaleX (defaults to the file's own
    name on disk) - lets the picker page rename the file before sending,
    same idea as ChituManager's own editable filename field.
    start_print: whether to actually start printing once each transfer
    lands (X-Start-Print / autoStart).

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
    item_id: if given, progress is published to SEND_STATUS[item_id] for the
    picker page's progress bar (GET /api/send-status)."""
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
        # printer itself, own_manager doesn't need to serialize on top of
        # that (that just makes a multi-printer send take N times longer
        # than it needs to for no reason).
        _set_send_status(item_id, "uploading", 5, "Готовим файл…")
        try:
            printers_by_id = {str(p.get("id")): p for p in fetch_printers()}
        except Exception as e:
            printers_by_id = {}
            logmsg("=== fetch_printers FAILED (send flow): %s ===", e)

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
            all_done = all(v["phase"] in ("done", "error") for v in vals)
            any_error = any(v["phase"] == "error" for v in vals)
            phase = "error" if (all_done and any_error) else ("done" if all_done else "sending")
            targets_out = [{"printerId": pid, "label": v["label"], "phase": v["phase"], "percent": v["percent"]}
                           for pid, v in items]
            _set_send_status(item_id, phase, percent, "", targets=targets_out)

        def _send_one(t):
            pid = t["printerId"]
            printer = printers_by_id.get(str(pid), {})
            label = printer.get("displayName") or printer.get("name") or pid
            with tracker_lock:
                tracker[pid] = {"label": label, "phase": "sending", "percent": 0.0}
            _report()

            def _cb(is_terminal, is_error, job_percent, message):
                with tracker_lock:
                    tracker[pid]["phase"] = "error" if is_error else ("done" if is_terminal else "sending")
                    if job_percent is not None:
                        tracker[pid]["percent"] = job_percent
                _report()

            patch = build_recommendation_patch(printer) if (t.get("applyRecommendations") and has_recommendations(printer)) else {}
            try:
                if patch:
                    status, resp_body = patch_and_upload_single(_get_draft_id(), pid, patch, start_print)
                    logmsg("=== PATCH+UPLOAD (startPrint=%s) -> %s: HTTP %d: %s ===",
                           start_print, pid, status, resp_body[:400].decode("utf-8", "replace"))
                else:
                    # Timings already fine for this printer (or no
                    # recommendations to apply) - skip the rewrite, send
                    # the file as-is.
                    status, resp_body = forward_to_scalex(file_path, pid, display_name=name, start_print=start_print)
                if 200 <= status < 300:
                    try:
                        upload_id = json.loads(resp_body.decode("utf-8", "replace")).get("uploadId")
                    except Exception:
                        upload_id = None
                    if upload_id:
                        poll_scalex_upload("/api/uploads/%s" % upload_id, name, progress_cb=_cb)
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


# ---------------------------------------------------------------------------
# Pending files waiting for a printer choice, and the HTTP server that
# serves the picker page + its small API.
# ---------------------------------------------------------------------------
PENDING = {}  # id -> {"file_path": str, "filename": str}
PENDING_LOCK = threading.Lock()
FIXED_HTTP_PORT = 8917  # stable, so you can bookmark/pin http://127.0.0.1:8917/
HTTP_PORT = 0  # filled in by start_http_server()
MANUAL_DIR = os.path.join(ROOT_DIR, "manual")  # files picked by hand, e.g. from CHITUBOX's own Save

PAGE_HTML = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Network sending \u2014 \u043a\u0443\u0434\u0430 \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u0444\u0430\u0439\u043b?</title>
<link rel="stylesheet" href="http://__SCALEX_HOST__:__SCALEX_PORT__/styles.css">
<style>
  /* ScaleX's own body background is a radial-gradient glow anchored near
     the top-right corner - subtle across their full dashboard, but this
     window is short/narrow enough that empty space below the card makes
     it read as a stray green smudge instead. Flat background here. */
  /* The list of printers is the only part that should ever need to
     scroll - the filename/search/filters above and the start-print
     checkbox + Send button below stay put and always visible, no matter
     how many printers are showing or how short the window is (was
     getting clipped at a fixed window height before: as more UI got added
     - machine notice, always-on prepared badges, etc - the fixed height
     that used to just barely fit stopped being enough, and would keep not
     being enough forever). */
  html, body { height: 100%; margin: 0; }
  body { display: flex; flex-direction: column; padding: 16px 20px 24px; font-size: 13px; background: var(--bg); }
  .card { max-width: 840px; margin: 0 auto; width: 100%; flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .card h1 { font-size: 17px; margin-bottom: 2px; }
  .card .eyebrow { font-size: 10px; }
  .card label { margin: 8px 0; font-size: 12px; }
  .card input, .card select { padding: 8px 10px; margin-top: 4px; font-size: 13px; }
  #form { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .toolbar-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin: 8px 0 8px; flex: 0 0 auto; }
  .filters-row { display: flex; align-items: center; gap: 10px; }
  #viewFiltersRow { margin: 6px 0 4px; flex: 0 0 auto; }
  #printerList {
    /* align-items:stretch makes two cards *in the same row* match each
       other's height when one has more content (a rec-row/badge the other
       doesn't); align-content:start is the other half of that - without
       it, a grid with room to spare (few printers, tall flex-allocated
       list area) stretches its row *tracks* to fill all of it too, which
       blows up a lone card to the whole panel's height instead of just
       matching its row-mate. */
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    align-items: stretch; align-content: start;
    gap: 8px 10px; flex: 1 1 auto; min-height: 120px; overflow-y: auto; padding-right: 4px; margin-bottom: 12px;
  }
  .bulk-printer-option { cursor: pointer; padding: 8px 10px; }
  .bulk-printer-option input[type="checkbox"] { cursor: pointer; }
  .bulk-printer-main strong { font-size: 12.5px; }
  .rec-row { grid-column: 2 / 3; margin-top: 2px; opacity: .65; font-size: 11px; }
  .op-prepared-badge { grid-column: 2 / 3; margin-top: 4px; width: fit-content; padding: 4px 8px; }
  .actions-row { display: flex; justify-content: end; gap: 10px; margin-top: 12px; flex: 0 0 auto; }
  #startPrintRow { margin-top: 8px; flex: 0 0 auto; }
  @media (max-width: 620px) {
    #printerList { grid-template-columns: 1fr; }
  }
  .progress-track { position: relative; height: 10px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--line); overflow: hidden; margin-top: 10px; }
  .progress-fill { height: 100%; width: 4%; border-radius: 999px; background: var(--accent); transition: width .35s ease, background .2s ease; }
  .progress-fill.indeterminate { width: 40% !important; animation: progress-slide 1.1s ease-in-out infinite; }
  @keyframes progress-slide { 0% { transform: translateX(-120%); } 100% { transform: translateX(280%); } }
  .mini-progress { grid-column: 2 / 3; margin-top: 6px; }
  .mini-progress .progress-track { margin-top: 4px; }
  .mini-progress-label { font-size: 11px; opacity: .75; margin-top: 3px; }
  .machine-notice { padding: 10px 12px; margin: 4px 0 8px; border-left: 3px solid var(--accent); border-radius: 4px; background: var(--panel-2); color: var(--accent); font-size: 12.5px; }
  a.logo-link { color: var(--accent); text-decoration: none; font-weight: 700; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; }
</style>
</head>
<body>
<div class="card">
  <div class="eyebrow"><a class="logo-link" href="http://__SCALEX_HOST__:__SCALEX_PORT__/" target="_blank">ScaleX LAN Manager</a> \u00b7 Network sending</div>
  <h1>\u041a\u0443\u0434\u0430 \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u0444\u0430\u0439\u043b?</h1>
  <p id="loadingNotice" class="notice">\u0417\u0430\u0433\u0440\u0443\u0436\u0430\u044e \u0441\u043f\u0438\u0441\u043e\u043a \u043f\u0440\u0438\u043d\u0442\u0435\u0440\u043e\u0432 \u0441 ScaleX\u2026</p>

  <div id="uploadZone" class="bulk-file-picker" style="display:none">
    <input type="file" id="fileInput" accept=".ctb,.goo,.cbddlp,.pwmx">
    <strong>\u0412\u044b\u0431\u0435\u0440\u0438 \u0438\u043b\u0438 \u043f\u0435\u0440\u0435\u0442\u0430\u0449\u0438 \u0444\u0430\u0439\u043b CTB / GOO</strong>
    <span>\u041d\u0430\u043f\u0440\u0438\u043c\u0435\u0440, \u0442\u043e\u0442, \u0447\u0442\u043e CHITUBOX \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u043b \u043e\u0431\u044b\u0447\u043d\u044b\u043c \u00abSave\u00bb \u2014 \u0431\u0435\u0437 ChituManager</span>
  </div>

  <div id="form" style="display:none">
    <label>\u0418\u043c\u044f \u0444\u0430\u0439\u043b\u0430 (\u043c\u043e\u0436\u043d\u043e \u0438\u0437\u043c\u0435\u043d\u0438\u0442\u044c \u043f\u0435\u0440\u0435\u0434 \u043e\u0442\u043f\u0440\u0430\u0432\u043a\u043e\u0439)
      <input type="text" id="filenameInput">
    </label>

    <label>\u041f\u043e\u0438\u0441\u043a \u043f\u0440\u0438\u043d\u0442\u0435\u0440\u0430
      <input type="search" id="search" placeholder="\u0438\u043c\u044f, IP, \u043c\u043e\u0434\u0435\u043b\u044c\u2026">
    </label>

    <p id="machineNotice" class="machine-notice" style="display:none"></p>

    <div class="filters-row" id="viewFiltersRow">
      <label class="checkbox compact"><input type="checkbox" id="onlineOnlyCb" checked><span>\u041f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0442\u044c \u0432\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0435</span></label>
      <label class="checkbox compact"><input type="checkbox" id="hideBusyCb" checked><span>\u0421\u043a\u0440\u044b\u0432\u0430\u0442\u044c \u0437\u0430\u043d\u044f\u0442\u044b\u0435</span></label>
      <label class="checkbox compact" id="matchOnlyRow" style="display:none"><input type="checkbox" id="matchOnlyCb" checked><span>\u041f\u043e\u0434\u0445\u043e\u0434\u0438\u0442 \u043f\u043e\u0434 \u0444\u0430\u0439\u043b</span></label>
    </div>

    <div class="toolbar-row">
      <div class="filters-row">
        <button type="button" class="secondary small-button" id="selectAllBtn">\u0412\u044b\u0431\u0440\u0430\u0442\u044c \u0432\u0441\u0435 \u0432\u0438\u0434\u0438\u043c\u044b\u0435</button>
        <button type="button" class="secondary small-button" id="clearAllBtn">\u0421\u043d\u044f\u0442\u044c \u0432\u0441\u0451</button>
      </div>
      <span class="bulk-selected-count" id="selectedCount">\u0412\u044b\u0431\u0440\u0430\u043d\u043e: 0</span>
    </div>

    <div id="printerList"></div>

    <label class="checkbox" id="startPrintRow">
      <input type="checkbox" id="startPrintCb">
      <span>\u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c \u043f\u0435\u0447\u0430\u0442\u044c \u0441\u0440\u0430\u0437\u0443 \u043f\u043e\u0441\u043b\u0435 \u043e\u0442\u043f\u0440\u0430\u0432\u043a\u0438</span>
    </label>

    <div class="actions-row">
      <button type="button" class="primary" id="sendBtn" disabled>\u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c</button>
    </div>
  </div>

  <div class="actions-row">
    <button type="button" class="secondary" id="closeWindowBtn" style="display:none">\u0417\u0430\u043a\u0440\u044b\u0442\u044c \u043e\u043a\u043d\u043e</button>
  </div>
</div>

<script>
const params = new URLSearchParams(location.search);
let pendingId = params.get('id');
let printers = [];
let detectedMachine = null;  // CTB's own embedded target-machine name, if found

function printerStateLabel(p) {
  const status = p.status || {};
  if (status.online === false || !p.status) return {cls: '', text: '\u041e\u0444\u0444\u043b\u0430\u0439\u043d'};
  if (isBusy(p)) return {cls: 'is-error', text: '\u041f\u0435\u0447\u0430\u0442\u0430\u0435\u0442'};
  return {cls: 'is-ready', text: '\u0414\u043e\u0441\u0442\u0443\u043f\u0435\u043d'};
}

function isBusy(p) {
  // Ported straight from ScaleX's own isPrinterPrintingStatus() (app.js) -
  // printStatusText alone has way more "doing something" values than just
  // "printing"/"exposing" (homing, lifting, preparing, pausing, ...), so a
  // short allowlist under-detects busy printers. This matches what the
  // real manager itself considers busy.
  const s = p.status || {};
  const currentStatus = Number(s.currentStatus ?? 0);
  const printStatus = Number(s.printStatus ?? 0);
  const text = String(s.printStatusText || '').toLowerCase();
  if (currentStatus === 0 || [8, 9].includes(printStatus) || ['idle', 'stopped', 'complete', 'completed'].includes(text)) {
    return false;
  }
  return currentStatus === 1 ||
    [1, 2, 3, 4, 5, 6, 7].includes(printStatus) ||
    ['preparing', 'homing', 'lifting', 'exposing', 'printing', 'pausing', 'paused', 'stopping'].includes(text);
}

function isOnline(p) {
  return !!(p.status && p.status.online === true);
}

function matchesMachine(p) {
  if (!detectedMachine) return true;
  const model = (p.model || p.machineModel || '').trim();
  if (!model) return true;  // printer has no model info - can't tell, don't hide it
  // Suffix match, not exact/substring: CHITUBOX sometimes glues a couple of
  // stray bytes onto the *front* of the embedded machine name (harmless
  // binary noise, confirmed by inspecting real captured files), and this
  // also correctly tells "Saturn 4 Ultra" apart from "Saturn 4 Ultra 16K"
  // (a plain substring check would match both against either file).
  return detectedMachine.toLowerCase().endsWith(model.toLowerCase());
}

function recSummary(p) {
  const parts = [];
  if (p.recommendedNormalExposure != null && p.recommendedNormalExposure !== '') parts.push('\u043e\u0431\u044b\u0447\u043d\u0430\u044f ' + p.recommendedNormalExposure + 's');
  if (p.recommendedBottomExposure != null && p.recommendedBottomExposure !== '') parts.push('\u043d\u0438\u0436\u043d\u044f\u044f ' + p.recommendedBottomExposure + 's');
  if (p.recommendedBottomLayers != null && p.recommendedBottomLayers !== '') parts.push(p.recommendedBottomLayers + ' \u043d\u0438\u0436\u043d\u0438\u0445 \u0441\u043b\u043e\u0451\u0432');
  return parts.join(', ');
}

function hasRec(p) {
  return (p.recommendedNormalExposure != null && p.recommendedNormalExposure !== '')
    || (p.recommendedBottomExposure != null && p.recommendedBottomExposure !== '')
    || (p.recommendedBottomLayers != null && p.recommendedBottomLayers !== '');
}

function renderList() {
  const q = document.getElementById('search').value.trim().toLowerCase();
  const list = document.getElementById('printerList');
  // Re-rendering (search/filters/live refresh) must not silently drop
  // whatever the user already ticked - capture it first, reapply after.
  const wasSelected = new Set(Array.from(list.querySelectorAll('.bulk-printer-select:checked')).map(b => b.value));
  const wasRecChecked = new Set(Array.from(list.querySelectorAll('.apply-rec:checked'))
    .map(cb => cb.closest('.bulk-printer-option').dataset.printerId));
  list.innerHTML = '';
  const onlineOnly = document.getElementById('onlineOnlyCb').checked;
  const hideBusy = document.getElementById('hideBusyCb').checked;
  const matchOnly = detectedMachine && document.getElementById('matchOnlyCb').checked;
  printers
    .filter(p => {
      if (onlineOnly && !isOnline(p)) return false;
      if (hideBusy && isBusy(p)) return false;
      if (matchOnly && !matchesMachine(p)) return false;
      if (!q) return true;
      const hay = [p.displayName, p.name, p.currentIp, p.model, p.machineModel].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    })
    .forEach(p => {
      const state = printerStateLabel(p);
      const name = p.displayName || p.name || p.liveName || p.id;
      const model = p.model || p.machineModel || '';
      const ip = p.currentIp || p.ipAddress || '';

      const opt = document.createElement('div');
      opt.className = 'bulk-printer-option';
      opt.dataset.printerId = p.id;

      const label = document.createElement('label');
      label.className = 'bulk-printer-choice';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'bulk-printer-select';
      cb.value = p.id;
      cb.checked = wasSelected.has(String(p.id));
      const main = document.createElement('span');
      main.className = 'bulk-printer-main';
      main.innerHTML = '<strong>' + name + '</strong><span>' + model + ' \u2014 ' + ip + '</span>';
      label.appendChild(cb);
      label.appendChild(main);
      opt.appendChild(label);

      const stateSpan = document.createElement('span');
      stateSpan.className = 'bulk-printer-state ' + state.cls;
      stateSpan.textContent = state.text;
      opt.appendChild(stateSpan);

      if (hasRec(p)) {
        const recRow = document.createElement('label');
        recRow.className = 'checkbox compact rec-row';
        const recCb = document.createElement('input');
        recCb.type = 'checkbox';
        recCb.className = 'apply-rec';
        recCb.checked = wasRecChecked.has(String(p.id));
        recRow.appendChild(recCb);
        recRow.appendChild(document.createTextNode('\u043f\u0440\u0438\u043c\u0435\u043d\u0438\u0442\u044c \u0440\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u0430\u0446\u0438\u0438: ' + recSummary(p)));
        opt.appendChild(recRow);
      }

      // Same grey/green pill ScaleX's own manager shows for this printer -
      // purely a visual read-out of whether it's confirmed safe to print
      // on (operatorPrepared), not something own_manager lets you toggle.
      const prep = document.createElement('span');
      prep.className = 'operator-prepared-toggle op-prepared-badge' + (p.operatorPrepared === true ? ' active' : '');
      prep.innerHTML = '<span class="prepared-dot"></span>' + (p.operatorPrepared === true ? '\u041f\u0440\u0438\u043d\u0442\u0435\u0440 \u043f\u043e\u0434\u0433\u043e\u0442\u043e\u0432\u043b\u0435\u043d' : '\u041d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d');
      opt.appendChild(prep);

      cb.addEventListener('change', updateSelectedCount);
      list.appendChild(opt);
    });
  updateSelectedCount();
}

function updateSelectedCount() {
  const boxes = Array.from(document.querySelectorAll('.bulk-printer-select'));
  const checked = boxes.filter(b => b.checked);
  document.getElementById('selectedCount').textContent = '\u0412\u044b\u0431\u0440\u0430\u043d\u043e: ' + checked.length;
  document.getElementById('sendBtn').disabled = checked.length === 0;
}

document.getElementById('search').addEventListener('input', renderList);
document.getElementById('onlineOnlyCb').addEventListener('change', renderList);
document.getElementById('hideBusyCb').addEventListener('change', renderList);
document.getElementById('matchOnlyCb').addEventListener('change', renderList);
document.getElementById('selectAllBtn').addEventListener('click', () => {
  document.querySelectorAll('.bulk-printer-select').forEach(b => { b.checked = true; b.dispatchEvent(new Event('change')); });
});
document.getElementById('clearAllBtn').addEventListener('click', () => {
  document.querySelectorAll('.bulk-printer-select').forEach(b => { b.checked = false; b.dispatchEvent(new Event('change')); });
});

const TARGET_PHASE_LABELS = {
  queued: '\u0412 \u043e\u0447\u0435\u0440\u0435\u0434\u0438',
  uploading: '\u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430',
  sending: '\u041f\u0435\u0440\u0435\u0434\u0430\u0447\u0430',
  done: '\u0413\u043e\u0442\u043e\u0432\u043e',
  error: '\u041e\u0448\u0438\u0431\u043a\u0430',
};

function setMiniProgress(opt, phase, percent, message) {
  const fill = opt.querySelector('.progress-fill');
  const label = opt.querySelector('.mini-progress-label');
  if (!fill || !label) return;
  if (phase === 'error') {
    fill.classList.remove('indeterminate');
    fill.style.width = '100%';
    fill.style.background = 'var(--red)';
    label.textContent = '\u041e\u0448\u0438\u0431\u043a\u0430' + (message ? ': ' + message : '');
    return;
  }
  if (phase === 'done') {
    fill.classList.remove('indeterminate');
    fill.style.width = '100%';
    label.textContent = '\u0413\u043e\u0442\u043e\u0432\u043e';
    return;
  }
  if (percent === null || percent === undefined) {
    fill.classList.add('indeterminate');
  } else {
    fill.classList.remove('indeterminate');
    fill.style.width = Math.max(4, Math.min(100, percent)) + '%';
  }
  label.textContent = (TARGET_PHASE_LABELS[phase] || phase) + (message ? ': ' + message : '');
}

function closeWindow() {
  if (window.pywebview && window.pywebview.api && window.pywebview.api.close) {
    window.pywebview.api.close();
  } else {
    window.close();  // e.g. opened in a plain browser tab instead of the native window
  }
}

document.getElementById('closeWindowBtn').addEventListener('click', closeWindow);

async function pollSendStatus() {
  let st;
  try {
    st = await (await fetch('/api/send-status?id=' + encodeURIComponent(pendingId))).json();
  } catch (e) {
    setTimeout(pollSendStatus, 1500);
    return;
  }
  const targetList = st.targets || [];
  let allDone = targetList.length > 0;
  targetList.forEach(t => {
    const opt = document.querySelector('.bulk-printer-option[data-printer-id="' + CSS.escape(String(t.printerId)) + '"]');
    if (!opt) return;
    setMiniProgress(opt, t.phase, t.percent, null);
    if (t.phase !== 'done' && t.phase !== 'error') allDone = false;
  });
  if (!allDone) {
    setTimeout(pollSendStatus, 700);
    return;
  }
  document.getElementById('closeWindowBtn').style.display = 'inline-flex';
}

document.getElementById('sendBtn').addEventListener('click', async () => {
  if (printerRefreshTimer) { clearInterval(printerRefreshTimer); printerRefreshTimer = null; }
  const nameInput = document.getElementById('filenameInput').value.trim();
  const options = Array.from(document.querySelectorAll('.bulk-printer-option'));
  const targets = [];
  const selectedIds = new Set();
  options.forEach(opt => {
    const cb = opt.querySelector('.bulk-printer-select');
    if (!cb.checked) return;
    const recCb = opt.querySelector('.apply-rec');
    targets.push({printerId: opt.dataset.printerId, applyRecommendations: !!(recCb && recCb.checked)});
    selectedIds.add(opt.dataset.printerId);
  });
  const startPrint = document.getElementById('startPrintCb').checked;

  // Lock the form instead of replacing it with a generic full-screen
  // status: keep only the printers actually being sent to, each gets its
  // own mini progress bar right under its card.
  document.getElementById('filenameInput').disabled = true;
  document.getElementById('viewFiltersRow').style.display = 'none';
  document.getElementById('search').closest('label').style.display = 'none';
  document.querySelector('.toolbar-row').style.display = 'none';
  document.getElementById('startPrintRow').style.display = 'none';
  document.querySelector('.actions-row').style.display = 'none';

  options.forEach(opt => {
    if (!selectedIds.has(opt.dataset.printerId)) {
      opt.style.display = 'none';
      return;
    }
    opt.querySelectorAll('input').forEach(inp => { inp.disabled = true; });
    const bar = document.createElement('div');
    bar.className = 'mini-progress';
    bar.innerHTML = '<div class="progress-track"><div class="progress-fill indeterminate"></div></div>'
      + '<div class="mini-progress-label">\u0412 \u043e\u0447\u0435\u0440\u0435\u0434\u0438\u2026</div>';
    opt.appendChild(bar);
  });

  const resp = await fetch('/api/send', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: pendingId, displayName: nameInput, targets: targets, startPrint: startPrint})
  });
  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    document.querySelectorAll('.bulk-printer-option').forEach(opt => setMiniProgress(opt, 'error', 100, payload.error || String(resp.status)));
    document.getElementById('closeWindowBtn').style.display = 'inline-flex';
    return;
  }
  pollSendStatus();
});

document.getElementById('filenameInput').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('search').focus(); });
document.getElementById('search').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('sendBtn').click(); });

let printerRefreshTimer = null;

async function refreshPrinters() {
  try {
    printers = await (await fetch('/api/printers')).json();
    printers.sort((a, b) => (a.displayName || a.name || '').localeCompare(b.displayName || b.name || ''));
    renderList();
  } catch (e) { /* keep showing the last known list, try again next tick */ }
}

async function loadPrintersAndShowForm(filename, machineName) {
  printers = await (await fetch('/api/printers')).json();
  printers.sort((a, b) => (a.displayName || a.name || '').localeCompare(b.displayName || b.name || ''));
  document.title = 'Network sending \u2014 ' + filename;
  document.getElementById('filenameInput').value = filename;
  document.getElementById('loadingNotice').style.display = 'none';
  document.getElementById('uploadZone').style.display = 'none';
  document.getElementById('form').style.display = 'flex';

  detectedMachine = (machineName || '').trim() || null;
  const machineNotice = document.getElementById('machineNotice');
  const matchRow = document.getElementById('matchOnlyRow');
  if (detectedMachine) {
    machineNotice.textContent = '\u041d\u0430\u0440\u0435\u0437\u0430\u043d\u043e \u043f\u043e\u0434: ' + detectedMachine;
    machineNotice.style.display = 'block';
    matchRow.style.display = 'flex';
  } else {
    machineNotice.style.display = 'none';
    matchRow.style.display = 'none';
  }

  renderList();
  // Printer status (online/busy/prepared) is polled live from ScaleX while
  // you're still deciding where to send - so toggling "\u043f\u043e\u0434\u0433\u043e\u0442\u043e\u0432\u043b\u0435\u043d" or a
  // print finishing on the real manager shows up here too, not just a
  // stale snapshot from the moment the picker opened. Stops the instant
  // Send is clicked (see sendBtn handler) so it can't clobber the
  // per-printer progress bars.
  printerRefreshTimer = setInterval(refreshPrinters, 5000);
}

async function uploadFile(file) {
  document.getElementById('loadingNotice').textContent = '\u0417\u0430\u0433\u0440\u0443\u0436\u0430\u044e ' + file.name + '\u2026';
  document.getElementById('loadingNotice').style.display = 'block';
  document.getElementById('uploadZone').style.display = 'none';
  const resp = await fetch('/api/manual-upload', {
    method: 'POST',
    headers: {'X-File-Name': encodeURIComponent(file.name)},
    body: file,
  });
  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    document.getElementById('loadingNotice').textContent = '\u041e\u0448\u0438\u0431\u043a\u0430: ' + (payload.error || resp.status);
    document.getElementById('uploadZone').style.display = 'grid';
    return;
  }
  pendingId = payload.id;
  history.replaceState(null, '', '?id=' + encodeURIComponent(pendingId));
  await loadPrintersAndShowForm(file.name, payload.machineName);
}

const fileInput = document.getElementById('fileInput');
const uploadZone = document.getElementById('uploadZone');
fileInput.addEventListener('change', () => { if (fileInput.files[0]) uploadFile(fileInput.files[0]); });
uploadZone.addEventListener('click', () => fileInput.click());
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault();
  uploadZone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
});

(async function init() {
  if (!pendingId) {
    // No captured file waiting - offer manual pick (e.g. something
    // CHITUBOX saved normally, no ChituManager involved at all).
    document.getElementById('loadingNotice').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'grid';
    return;
  }
  const pendingResp = await fetch('/api/pending?id=' + encodeURIComponent(pendingId));
  if (!pendingResp.ok) {
    document.getElementById('loadingNotice').textContent = '\u042d\u0442\u043e\u0442 \u0444\u0430\u0439\u043b \u0443\u0436\u0435 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u0430\u043d \u0438\u043b\u0438 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d.';
    return;
  }
  const pending = await pendingResp.json();
  await loadPrintersAndShowForm(pending.filename, pending.machineName);
})();
</script>
</body>
</html>
"""


def _render_page():
    return PAGE_HTML.replace("__SCALEX_HOST__", SCALEX_HOST).replace("__SCALEX_PORT__", str(SCALEX_PORT)).encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send_bytes(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status, obj):
        self._send_bytes(status, "application/json", json.dumps(obj).encode("utf-8"))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}

        if path == "/" or path == "/index.html":
            self._send_bytes(200, "text/html; charset=utf-8", _render_page())
            return

        if path == "/api/pending":
            item_id = (query.get("id") or [None])[0]
            with PENDING_LOCK:
                item = PENDING.get(item_id)
            if not item:
                self._send_json(404, {"error": "not found"})
                return
            self._send_json(200, {"filename": item["filename"], "machineName": item.get("machine_name")})
            return

        if path == "/api/printers":
            try:
                self._send_json(200, fetch_printers())
            except Exception as e:
                logmsg("=== /api/printers proxy FAILED: %s ===", e)
                self._send_json(200, [])
            return

        if path == "/api/send-status":
            item_id = (query.get("id") or [None])[0]
            with SEND_STATUS_LOCK:
                st = SEND_STATUS.get(item_id)
            self._send_json(200, st or {"phase": "unknown"})
            return

        self._send_bytes(404, "text/plain", b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]

        if path == "/api/manual-upload":
            # Manual path: pick any local file you've already saved
            # yourself (e.g. via CHITUBOX's own plain "Save", no manager
            # involved at all) and hand it to own_manager directly, same
            # idea as the automatic SlicerFile capture. Raw bytes as body,
            # like every other upload in this file - X-File-Name header
            # names it.
            raw_name = self.headers.get("X-File-Name", "")
            try:
                filename = urllib.parse.unquote(raw_name) or "upload.ctb"
            except Exception:
                filename = "upload.ctb"
            filename = os.path.basename(filename)  # no path traversal via the header
            if not filename.lower().endswith(SLICE_EXTENSIONS):
                self._send_json(400, {"error": "Только файлы: " + ", ".join(SLICE_EXTENSIONS)})
                return
            if not body:
                self._send_json(400, {"error": "empty upload"})
                return
            try:
                os.makedirs(MANUAL_DIR, exist_ok=True)
                dest = os.path.join(MANUAL_DIR, filename)
                base, ext = os.path.splitext(dest)
                n = 1
                while os.path.exists(dest):
                    dest = "%s (%d)%s" % (base, n, ext)
                    n += 1
                with open(dest, "wb") as f:
                    f.write(body)
            except Exception as e:
                logmsg("=== manual-upload FAILED: %s (%s) ===", filename, e)
                self._send_json(500, {"error": str(e)})
                return

            item_id = uuid.uuid4().hex
            machine_name = extract_ctb_machine_name(dest)
            with PENDING_LOCK:
                PENDING[item_id] = {"file_path": dest, "filename": os.path.basename(dest), "machine_name": machine_name}
            logmsg("=== MANUAL UPLOAD: %s (%d bytes) id=%s machine=%r ===", dest, len(body), item_id, machine_name)
            self._send_json(200, {"id": item_id, "machineName": machine_name})
            return

        try:
            data = json.loads(body.decode("utf-8", "replace")) if body else {}
        except Exception:
            data = {}

        if path == "/api/send":
            item_id = data.get("id")
            with PENDING_LOCK:
                item = PENDING.pop(item_id, None)
            with _pending_windows_lock:
                _pending_windows.pop(item_id, None)
            if not item:
                self._send_json(404, {"error": "unknown or already-handled id"})
                return
            targets = data.get("targets") or []
            if not targets:
                self._send_json(400, {"error": "no printers selected"})
                return
            display_name = (data.get("displayName") or "").strip() or item["filename"]
            src_ext = os.path.splitext(item["filename"])[1]
            if src_ext and not display_name.lower().endswith(src_ext.lower()):
                display_name += src_ext
            start_print = bool(data.get("startPrint"))
            logmsg("=== PICKER: sending %s as \"%s\" -> %s (startPrint=%s) ===",
                   item["filename"], display_name, json.dumps(targets), start_print)
            send_in_background(item["file_path"], targets, display_name=display_name,
                                start_print=start_print, item_id=item_id)
            self._send_json(200, {"ok": True})
            return

        self._send_bytes(404, "text/plain", b"")


def start_http_server():
    global HTTP_PORT
    try:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", FIXED_HTTP_PORT), Handler)
    except OSError as e:
        logmsg("=== port %d busy (%s), falling back to a random port ===", FIXED_HTTP_PORT, e)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    HTTP_PORT = httpd.server_address[1]
    logmsg("=== HTTP server listening on 127.0.0.1:%d ===", HTTP_PORT)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return HTTP_PORT


def register_pending(dest_path):
    """Add a captured file to PENDING and open the picker page for it."""
    item_id = uuid.uuid4().hex
    filename = os.path.basename(dest_path)
    machine_name = extract_ctb_machine_name(dest_path)
    with PENDING_LOCK:
        PENDING[item_id] = {"file_path": dest_path, "filename": filename, "machine_name": machine_name}
    url = "http://127.0.0.1:%d/?id=%s" % (HTTP_PORT, item_id)
    logmsg("=== OPENING PICKER: %s (machine=%r) ===", url, machine_name)
    open_app_window("Network sending — %s" % filename, url, item_id=item_id)


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
    idx = buf.find(marker)
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

REQUEST_COOLDOWN_SEC = 4.0  # collapse CHITUBOX's retry-burst pings into one request


def handle_client(conn, addr):
    logmsg("=== CLIENT CONNECTED from %s:%d ===", addr[0], addr[1])
    last_request_ts = 0.0
    awaiting_path = None
    slice_label = "network_send"
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            try:
                text = chunk.decode("utf-8", "replace")
            except Exception:
                text = ""
            logmsg("RECV(%d): %s", len(chunk), text[:800])

            label = extract_field(text, '"SliceFileName": "')
            if label:
                slice_label = os.path.splitext(label)[0]

            # The reply to our own SaveFile request: {"MsgType":"SaveFile","Data":{"SavePath":...}}
            if '"MsgType": "SaveFile"' in text and awaiting_path:
                save_path = extract_field(text, '"SavePath": "')
                logmsg("=== SaveFile reply: SavePath=%s (awaiting=%s) ===", save_path, awaiting_path)
                candidate = save_path or awaiting_path
                candidate = candidate.replace("/", os.sep)
                if os.path.isfile(candidate):
                    try:
                        os.makedirs(RECEIVED_DIR, exist_ok=True)
                        dest = os.path.join(RECEIVED_DIR, os.path.basename(candidate))
                        shutil.copy2(candidate, dest)
                        logmsg("=== CTB CAPTURED via direct request: %s -> %s (%d bytes) ===",
                               candidate, dest, os.path.getsize(dest))
                        register_pending(dest)
                    except Exception as e:
                        logmsg("=== capture after SaveFile reply FAILED: %s (%s) ===", candidate, e)
                else:
                    logmsg("=== SaveFile reply but file not found at %s ===", candidate)
                awaiting_path = None

            if '"MsgType": "LoadWindow"' in text and '"WinType"' in text:
                sent = conn.send(LOADWINDOW_REPLY)
                logmsg("SENT (%d bytes) LoadWindow reply", sent)

                if '"Visible": true' in text:
                    now = time.monotonic()
                    if now - last_request_ts >= REQUEST_COOLDOWN_SEC:
                        last_request_ts = now
                        os.makedirs(PENDING_DIR, exist_ok=True)
                        target = os.path.join(PENDING_DIR, "%s_%s.ctb" % (slice_label, uuid.uuid4().hex[:8]))
                        awaiting_path = target
                        request = json.dumps({"MsgType": "SaveFile", "FilePath": target.replace("\\", "/")})
                        conn.send((request + "\n").encode("utf-8"))
                        logmsg("=== REQUESTED SaveFile: %s ===", target)
                    else:
                        logmsg("  -> Visible:true within cooldown (%.1fs ago), not requesting again",
                               now - last_request_ts)
    finally:
        logmsg("=== CLIENT DISCONNECTED ===")
        conn.close()


# ---------------------------------------------------------------------------
# Filesystem watcher - backstop. Catches the sliced file if it ever ends up
# in ChituManager's own SlicerFile folder some other way (e.g. someone
# runs the real ChituManager manually) even when the direct TCP request
# above is what's actually driving things day to day.
# ---------------------------------------------------------------------------
def slicer_file_watcher():
    logmsg("=== slicer_file_watcher: watching %s ===", SLICER_WATCH_DIR)
    seen = set()
    if os.path.isdir(SLICER_WATCH_DIR):
        for dirpath, _dirnames, filenames in os.walk(SLICER_WATCH_DIR):
            for name in filenames:
                seen.add(os.path.join(dirpath, name))

    while True:
        try:
            if os.path.isdir(SLICER_WATCH_DIR):
                for dirpath, _dirnames, filenames in os.walk(SLICER_WATCH_DIR):
                    for name in filenames:
                        if not name.lower().endswith(SLICE_EXTENSIONS):
                            continue
                        path = os.path.join(dirpath, name)
                        if path in seen:
                            continue
                        seen.add(path)

                        last_size = -1
                        for _ in range(30):  # up to ~6s
                            try:
                                size = os.path.getsize(path)
                            except OSError:
                                size = -1
                            if size == last_size and size > 0:
                                break
                            last_size = size
                            time.sleep(0.2)

                        try:
                            os.makedirs(RECEIVED_DIR, exist_ok=True)
                            dest = os.path.join(RECEIVED_DIR, os.path.basename(path))
                            shutil.copy2(path, dest)
                            logmsg("=== SLICER FILE CAPTURED: %s -> %s (%d bytes) ===",
                                   path, dest, os.path.getsize(dest))
                        except Exception as e:
                            logmsg("=== SLICER FILE CAPTURE FAILED: %s (%s) ===", path, e)
                            continue

                        register_pending(dest)
        except Exception as e:
            logmsg("=== slicer_file_watcher error: %s ===", e)
        time.sleep(POLL_INTERVAL_SEC)


def _chitubox_accept_loop(listen_sock):
    while True:
        try:
            conn, addr = listen_sock.accept()
        except Exception as e:
            logmsg("=== CHITUBOX accept() FAILED, listener socket is likely dead: %s ===", e)
            return
        try:
            handle_client(conn, addr)
        except Exception as e:
            # A single bad connection (CHITUBOX closed unexpectedly, a
            # malformed message, whatever) must not take down the whole
            # listener - this used to be one try/except wrapping the
            # entire while loop, so any exception out of handle_client
            # silently ended the thread and CHITUBOX could never connect
            # again until a manual restart, with only one easy-to-miss log
            # line to explain why.
            logmsg("=== handle_client FAILED for %s:%d, listener stays up: %s ===", addr[0], addr[1], e)


def main():
    logmsg("=== own_manager started PID=%d ===", os.getpid())
    logmsg("=== ScaleX: http://%s:%d ===", SCALEX_HOST, SCALEX_PORT)

    start_http_server()
    while HTTP_PORT == 0:
        time.sleep(0.05)

    threading.Thread(target=slicer_file_watcher, daemon=True).start()
    threading.Thread(target=_pending_cleanup_loop, daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", 0))
    port = listen_sock.getsockname()[1]
    logmsg("=== CHITUBOX protocol listening on 127.0.0.1:%d ===", port)
    listen_sock.listen(5)

    ok = create_shared_memory(SHM_NAME, str(port))
    logmsg("=== shared memory created=%s ===", "yes" if ok else "NO")
    if not ok:
        print("FAILED to create shared memory segment - see log. Exiting.")
        return 1

    # CHITUBOX only ever opens one persistent connection - handling it in a
    # background thread frees up the main thread for pywebview, which
    # insists on owning it (webview.start() below blocks here forever).
    threading.Thread(target=_chitubox_accept_loop, args=(listen_sock,), daemon=True).start()

    # pywebview needs at least one window to exist before start() - this
    # tiny hidden one just keeps its event loop alive; real picker windows
    # get created on demand by open_app_window() from any thread once
    # start() is running.
    webview.create_window("own_manager", "about:blank", hidden=True, width=1, height=1)

    print("own_manager running. Log: %s" % LOG_PATH)
    print("Picker UI: http://127.0.0.1:%d/  (opens automatically on each capture)" % HTTP_PORT)
    print("Close this window / Ctrl+C to stop (CHITUBOX will fall back to launching the real ChituManager).")

    try:
        webview.start(debug=False)
    except KeyboardInterrupt:
        pass
    finally:
        logmsg("=== own_manager exiting ===")
        _logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
