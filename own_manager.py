"""
own_manager.py - forwards every file CHITUBOX sends over "Network Sending"
to one or more printers on your own ScaleX LAN Manager farm. A native Qt
(PySide6) window pops up for each captured file, letting you rename it,
pick printers (checkboxes), and apply each printer's own recommended
exposure settings - with a tray icon so it's clear it's running and easy to
exit from there.

Run: python own_manager.py
Requires: PySide6 (pip install PySide6), pycryptodome (optional, see
extract_ctb_machine_name).
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

The picker UI has gone through three approaches now, in order: (1) tkinter
(a plain native popup); (2) a page served by own_manager's own local HTTP
server, reusing ScaleX's real stylesheet live over the network
(http://<scalex host>/styles.css) so it looked like a genuine part of the
same app - worked well visually, but needed an embedded browser (pywebview,
backed by the WebView2 runtime) to host it, and that embedded-browser layer
was the direct cause of two real production freezes (cross-thread WebView2
calls, then AttachThreadInput for window focus - see git history/PR #1 for
the second one). This version (3) drops the browser entirely: native Qt
(PySide6) widgets, styled via QSS instead of the real CSS (QSS is a
different, more limited language - can't just reuse styles.css as-is; see
COLOR_*/PICKER_QSS below, currently a placeholder dark theme written
without network access to copy ScaleX's actual colors). One process, no
multi-process browser engine, and progress reporting goes straight from a
background thread to the GUI via Qt signals (auto-thread-marshaled) instead
of a polling HTTP API.

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
import urllib.parse
from ctypes import wintypes

from PySide6.QtCore import Qt, QObject, Signal, QTimer
from PySide6.QtGui import QIcon, QPixmap, QColor, QAction, QCursor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QCheckBox, QPushButton, QScrollArea, QProgressBar,
    QSystemTrayIcon, QMenu, QFileDialog, QSizePolicy, QFrame, QMessageBox,
)

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
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.LPVOID, wintypes.UINT]
user32.SystemParametersInfoW.restype = wintypes.BOOL
user32.keybd_event.argtypes = [wintypes.BYTE, wintypes.BYTE, wintypes.DWORD, ctypes.c_void_p]
user32.keybd_event.restype = None
SPI_GETFOREGROUNDLOCKTIMEOUT = 0x2000
SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001
SPIF_SENDCHANGE = 0x2
VK_MENU = 0x12          # Alt
KEYEVENTF_KEYUP = 0x0002


def force_window_to_foreground(qwidget):
    """A native Qt window created (indirectly, via a queued signal - see
    AppController below) while some other app is in the foreground - e.g.
    CHITUBOX, right after the "Отправка по сети" click - doesn't reliably
    grab focus on its own either; same underlying Windows restriction that
    made the old pywebview version need a trick here too. Does NOT use
    AttachThreadInput (an earlier version of this trick did, for the
    pywebview build - see git history/PR #1 - it ties this thread's input
    queue to whatever process currently owns the foreground, and can freeze
    both windows if that process is even briefly busy at that exact
    moment).

    Zeroing the system-wide foreground-lock timeout alone (the only trick
    this used to do) turned out NOT to be enough on its own - confirmed
    live 2026-08-21: the log showed "SetForegroundWindow declined" on every
    single call, and the user reported the picker always just sits in the
    taskbar needing a manual click. The lock-timeout value only controls
    how long Windows waits before giving up and flashing the taskbar
    button instead of switching - modern Windows (10/11) separately checks
    whether the calling process looks like it just received real user
    input before honoring SetForegroundWindow from a background process at
    all, and own_manager (reacting to a background thread's signal) never
    does. The standard, widely-documented workaround for that second check:
    synthesize a harmless Alt keydown/keyup via keybd_event right before
    asking - this only feeds this process's own synthetic input queue, it
    does NOT touch any other process/thread's state the way
    AttachThreadInput does, so it doesn't carry the freeze risk that got
    AttachThreadInput ruled out above."""
    hwnd = int(qwidget.winId())
    old_timeout = wintypes.DWORD(0)
    user32.SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, ctypes.byref(old_timeout), 0)
    user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, 0, 0)
    try:
        user32.keybd_event(VK_MENU, 0, 0, None)              # Alt down
        user32.keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, None)  # Alt up

        if qwidget.isMinimized():
            qwidget.showNormal()

        ok = user32.SetForegroundWindow(hwnd)
        if not ok:
            logmsg("=== force_window_to_foreground: SetForegroundWindow declined even after the Alt-keypress trick (window stays open, just not raised) ===")
        # Cheap Qt-level fallbacks - cost nothing, occasionally succeed even
        # when the raw WinAPI call above is declined.
        qwidget.raise_()
        qwidget.activateWindow()
    finally:
        user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, old_timeout.value, 0)

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


def poll_scalex_upload(path, filename, timeout_sec=1800, interval_sec=2.0, progress_cb=None):
    """Generic poller for GET {path} - works for both /api/uploads/{id} and
    /api/bulk-uploads/{id} as long as the response has a "done" bool.
    progress_cb, if given, is called on every tick as
    progress_cb(is_terminal, is_error, job_percent_0_100_or_None, message) -
    lets a caller polling several printers concurrently (see
    send_in_background) aggregate them itself and report to its own GUI."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=15)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
        except Exception as e:
            logmsg("=== upload status check failed for %s (%s): %s ===", filename, path, e)
            if progress_cb:
                progress_cb(True, True, None, "Не удалось получить статус: %s" % e)
            return
        finally:
            conn.close()
        try:
            status = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            logmsg("=== upload status for %s: non-JSON response, giving up polling ===", filename)
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
        if progress_cb:
            progress_cb(is_terminal, is_error, job_percent, message)
        if is_terminal:
            logmsg("=== UPLOAD STATUS %s: %s ===", filename, json.dumps(status)[:500])
            return
        time.sleep(interval_sec)
    logmsg("=== upload status poll timed out for %s ===", filename)
    if progress_cb:
        progress_cb(True, True, None, "Тайм-аут ожидания статуса")


def send_in_background(file_path, targets, display_name=None, start_print=False, report_cb=None):
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
        # printer itself, own_manager doesn't need to serialize on top of
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
            all_done = all(v["phase"] in ("done", "error") for v in vals)
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
# Picker GUI - native Qt widgets (PySide6), styled via QSS below to look like
# a dashboard panel instead of a generic OS dialog. Replaces the old
# pywebview + local-HTTP-server + PAGE_HTML approach entirely: no browser
# engine, no HTTP server, no polling - printer/send progress goes straight
# from a worker thread to the GUI thread via Qt signals (thread-safe by
# construction: Qt auto-queues delivery when emitter and receiver live on
# different threads, no PostMessage/AttachThreadInput-style plumbing needed
# the way the old WebView2-based attempts required).
#
# Real values, copied byte-for-byte from ScaleX's own styles.css :root
# block and its actual rules for the specific pieces this window mirrors
# (2026-08-21, http://<scalex host>:<port>/styles.css - fetch it again and
# diff against this block if ScaleX's theme ever changes):
#   :root { --bg:#111315; --panel:#1a1d20; --panel-2:#22262a; --line:#31363b;
#            --text:#f4f1ea; --muted:#999f9f; --accent:#e8ff65;
#            --green:#73d49a; --red:#ff7e78; }
#   input,select,textarea { background:#111416; border:1px solid var(--line); border-radius:8px; }
#   .bulk-printer-option { background:#15181a; border-radius:9px; }  <- printer cards specifically, NOT --panel
#   .bulk-printer-option:has(:checked) { border-color: rgba(232,255,101,.65); background: rgba(232,255,101,.06); }
#   .bulk-printer-state.is-ready { color: var(--green); }   <- NOT --accent, ScaleX uses green for "ready"
#   .bulk-printer-state.is-error { color: var(--red); }
#   .operator-prepared-toggle.active { color: var(--green); border-color: rgba(115,212,154,.7); background: rgba(115,212,154,.12); }
#   .primary { background: var(--accent); color: #12140c; font-weight:700; border-radius:9px; padding:10px 15px; }
#   .primary:disabled { background:#25292c; color: var(--muted); }
#   button { border:1px solid var(--line); border-radius:9px; padding:10px 15px; background: var(--panel); }
#   font-family: "Segoe UI", Arial, sans-serif;
# Every color the picker uses funnels through these constants and
# PICKER_QSS below - re-derive from the real stylesheet, don't hand-tune
# hex values here directly.
# ---------------------------------------------------------------------------
COLOR_BG = "#111315"
COLOR_PANEL = "#1a1d20"
COLOR_PANEL_2 = "#22262a"
COLOR_LINE = "#31363b"
COLOR_TEXT = "#f4f1ea"
COLOR_TEXT_DIM = "#999f9f"
COLOR_ACCENT = "#e8ff65"
COLOR_ACCENT_TEXT = "#12140c"  # text painted ON TOP of an accent-colored surface (.primary)
COLOR_GREEN = "#73d49a"        # "ready"/"prepared" state - ScaleX does NOT reuse accent for this
COLOR_RED = "#ff7e78"
COLOR_CARD_BG = "#15181a"      # printer cards specifically - distinct from --panel, not a typo
COLOR_INPUT_BG = "#111416"     # text inputs specifically - distinct from --panel, not a typo
FONT_FAMILY = "Segoe UI"

PICKER_QSS = """
* { font-family: "%(font)s"; }
QMainWindow, #pickerCentral, #pickerScrollContents { background: %(bg)s; }
QLabel { color: %(text)s; }
#eyebrowLabel { color: %(accent)s; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
#headingLabel { color: %(text)s; font-size: 17px; font-weight: 700; }
#fieldLabel { color: %(dim)s; font-size: 11.5px; }
#machineNotice { background: %(panel2)s; color: %(accent)s; border-left: 3px solid %(accent)s;
    border-radius: 4px; padding: 8px 10px; }
#selectedCountLabel { color: %(dim)s; font-size: 11.5px; }
QLineEdit { background: %(inputbg)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 8px; padding: 8px 10px; }
QLineEdit:focus { border: 1px solid %(accent)s; }
QLineEdit:disabled { color: %(dim)s; }
QCheckBox { color: %(text)s; spacing: 6px; }
QCheckBox:disabled { color: %(dim)s; }
QPushButton { background: %(panel)s; color: %(text)s; border: 1px solid %(line)s;
    border-radius: 9px; padding: 9px 15px; }
QPushButton:hover { border: 1px solid %(accent)s; }
QPushButton:disabled { color: %(dim)s; }
#sendBtn { background: %(accent)s; color: %(accenttext)s; font-weight: 700; border: none; }
#sendBtn:disabled { background: #25292c; color: %(dim)s; }
QScrollArea { border: none; background: transparent; }
#printerRow { background: %(cardbg)s; border: 1px solid %(line)s; border-radius: 9px; }
#printerRow[selected="true"] { border: 1px solid rgba(232, 255, 101, .65); background: rgba(232, 255, 101, .06); }
#printerName { color: %(text)s; font-size: 12.5px; font-weight: 700; }
#printerMeta { color: %(dim)s; font-size: 11.5px; }
#stateLabel[state="ready"] { color: %(green)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="busy"] { color: %(red)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="offline"] { color: %(dim)s; font-size: 11px; font-weight: 600; }
#recSummary { color: %(dim)s; font-size: 11px; }
#miniProgressLabel { color: %(dim)s; font-size: 11px; }
QProgressBar { background: %(panel2)s; border: 1px solid %(line)s; border-radius: 5px;
    max-height: 8px; min-height: 8px; text-align: center; color: transparent; }
QProgressBar::chunk { background: %(accent)s; border-radius: 5px; }
""" % {
    "bg": COLOR_BG, "panel": COLOR_PANEL, "panel2": COLOR_PANEL_2, "line": COLOR_LINE,
    "text": COLOR_TEXT, "dim": COLOR_TEXT_DIM, "accent": COLOR_ACCENT,
    "accenttext": COLOR_ACCENT_TEXT, "green": COLOR_GREEN, "red": COLOR_RED,
    "cardbg": COLOR_CARD_BG, "inputbg": COLOR_INPUT_BG, "font": FONT_FAMILY,
}


# ---------------------------------------------------------------------------
# Printer filter/status helpers - ported straight from the old PAGE_HTML's
# JS (isBusy/isOnline/matchesMachine), which itself mirrors ScaleX's own
# isPrinterPrintingStatus() (app.js). Kept as plain functions so the same
# logic could be unit-tested or reused outside the GUI later.
# ---------------------------------------------------------------------------
_BUSY_IDLE_TEXT = ("idle", "stopped", "complete", "completed")
_BUSY_TEXT = ("preparing", "homing", "lifting", "exposing", "printing", "pausing", "paused", "stopping")


def printer_is_uploading(p):
    """True while ScaleX still has an active (non-final) upload job
    targeting this printer - i.e. it's already receiving a file right now,
    from someone else's send or a previous own_manager batch. printStatus
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


TARGET_PHASE_LABELS = {
    "queued": "В очереди",
    "uploading": "Загрузка",
    "sending": "Передача",
    "done": "Готово",
    "error": "Ошибка",
}

ERROR_REASON_LABELS = {
    "low_memory": "Недостаточно памяти на принтере",
}


class PrinterRowWidget(QFrame):
    """One printer card - persists for the printer's whole lifetime in this
    window (created once when first seen, updated in place on every 5s
    refresh) so filtering/searching never has to save-and-restore checkbox
    state the way the old JS page did (it had to destroy+recreate DOM nodes
    on every re-render; a native widget just gets hidden/shown/repositioned
    instead, so nothing needs to remember what was checked)."""

    def __init__(self, printer, parent=None):
        super().__init__(parent)
        self.setObjectName("printerRow")
        self.setCursor(Qt.PointingHandCursor)
        self.printer_id = str(printer.get("id"))
        self.printer = printer
        self._has_rec = False  # set for real by apply_data() below; only matters before that if something toggles early

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(4)

        top = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.toggled.connect(self._on_checkbox_toggled)
        top.addWidget(self.checkbox)

        names = QVBoxLayout()
        names.setSpacing(0)
        self.name_label = QLabel()
        self.name_label.setObjectName("printerName")
        self.meta_label = QLabel()
        self.meta_label.setObjectName("printerMeta")
        names.addWidget(self.name_label)
        names.addWidget(self.meta_label)
        top.addLayout(names, 1)

        self.state_label = QLabel()
        self.state_label.setObjectName("stateLabel")
        top.addWidget(self.state_label, 0, Qt.AlignTop)
        outer.addLayout(top)

        # Purely informational labels must not swallow the click - Qt gives
        # the deepest widget under the cursor first dibs at a mouse event
        # and, unlike some event types, an ignored mouse press does NOT
        # automatically bubble up to the parent - so without this, clicking
        # directly on the printer name/meta/state text would do nothing
        # instead of reaching mousePressEvent() below and toggling
        # selection like clicking the empty background already does.
        for lbl in (self.name_label, self.meta_label, self.state_label):
            lbl.setAttribute(Qt.WA_TransparentForMouseEvents, True)

        self.rec_row = QWidget()
        rec_layout = QHBoxLayout(self.rec_row)
        rec_layout.setContentsMargins(24, 0, 0, 0)
        rec_layout.setSpacing(6)
        self.rec_checkbox = QCheckBox("применить рекомендации:")
        self.rec_summary_label = QLabel()
        self.rec_summary_label.setObjectName("recSummary")
        rec_layout.addWidget(self.rec_checkbox)
        rec_layout.addWidget(self.rec_summary_label, 1)
        outer.addWidget(self.rec_row)

        self.mini_progress = QProgressBar()
        self.mini_progress.setRange(0, 100)
        self.mini_progress_label = QLabel()
        self.mini_progress_label.setObjectName("miniProgressLabel")
        mini_wrap = QVBoxLayout()
        mini_wrap.setContentsMargins(24, 2, 0, 0)
        mini_wrap.setSpacing(2)
        mini_wrap.addWidget(self.mini_progress)
        mini_wrap.addWidget(self.mini_progress_label)
        self.mini_progress_widget = QWidget()
        self.mini_progress_widget.setLayout(mini_wrap)
        self.mini_progress_widget.setVisible(False)
        outer.addWidget(self.mini_progress_widget)

        self.on_selection_changed = None  # set by PickerWindow
        self.apply_data(printer)

    def mousePressEvent(self, event):
        """Click-to-select: anywhere on the card toggles the same checkbox
        as clicking the checkbox itself (per user request 2026-08-25) - the
        checkbox and rec_checkbox keep their own normal click handling
        since Qt routes a mouse event to the deepest widget under the
        cursor first, and only an unclaimed click (background, or one of
        the labels marked WA_TransparentForMouseEvents above) reaches
        here."""
        if event.button() == Qt.LeftButton and self.checkbox.isEnabled():
            self.checkbox.toggle()
            event.accept()
            return
        super().mousePressEvent(event)

    def _on_checkbox_toggled(self, checked):
        self.setProperty("selected", "true" if checked else "false")
        self.style().unpolish(self)
        self.style().polish(self)

        # Recommendations only matter once you've actually chosen to send
        # here, so keep them out of sight otherwise (per user request
        # 2026-08-25) - and once a printer IS selected, apply its
        # recommended exposure by default rather than making that an extra
        # click every time; the checkbox stays a real override if someone
        # wants to turn it back off for this send.
        self.rec_row.setVisible(checked and self._has_rec)
        if checked and self._has_rec:
            self.rec_checkbox.setChecked(True)

        if self.on_selection_changed:
            self.on_selection_changed()

    def apply_data(self, printer):
        """Refresh from a fresh /api/printers snapshot (live 5s refresh) -
        never touches self.checkbox/self.rec_checkbox so the user's current
        selection survives a background refresh."""
        self.printer = printer
        name = printer.get("displayName") or printer.get("name") or printer.get("liveName") or printer.get("id")
        model = printer.get("model") or printer.get("machineModel") or ""
        ip = printer.get("currentIp") or printer.get("ipAddress") or ""
        self.name_label.setText(str(name))
        self.meta_label.setText("%s — %s" % (model, ip) if model or ip else "")

        prepared = printer.get("operatorPrepared") is True
        if not printer.get("status") or printer.get("status", {}).get("online") is False:
            state, text = "offline", "Оффлайн"
        elif printer_is_uploading(printer):
            state, text = "busy", "Загружается"
        elif printer_is_busy(printer):
            state, text = "busy", "Печатает"
        elif prepared:
            # Merged with the old separate "Принтер подготовлен" badge/row
            # (per user request 2026-08-25) - "prepared" only has anything
            # useful to add once the printer is otherwise available; folded
            # into the same label instead of its own line.
            state, text = "ready", "Доступен и подготовлен"
        else:
            state, text = "ready", "Доступен"
        self.state_label.setText(text)
        self.state_label.setProperty("state", state)
        self.state_label.style().unpolish(self.state_label)
        self.state_label.style().polish(self.state_label)

        summary = printer_rec_summary(printer)
        self._has_rec = bool(summary)
        if self._has_rec:
            self.rec_summary_label.setText(summary)
        self.rec_row.setVisible(self._has_rec and self.checkbox.isChecked())

    def matches_filters(self, query, online_only, hide_busy, match_only, detected_machine):
        if online_only and not printer_is_online(self.printer):
            return False
        if hide_busy and printer_is_busy(self.printer):
            return False
        if match_only and not printer_matches_machine(self.printer, detected_machine):
            return False
        if query:
            hay = " ".join(str(self.printer.get(k) or "") for k in
                            ("displayName", "name", "currentIp", "model", "machineModel")).lower()
            if query not in hay:
                return False
        return True

    def set_locked_for_send(self, selected):
        """Called once when a send starts: hides unselected cards, disables
        inputs on the selected ones, and reveals their mini progress bar -
        mirrors the old JS's sendBtn handler, which locked the whole form
        and gave each selected printer its own progress bar in place."""
        self.setVisible(selected)
        if not selected:
            return
        self.checkbox.setEnabled(False)
        self.rec_checkbox.setEnabled(False)
        self.mini_progress_widget.setVisible(True)
        self.mini_progress.setRange(0, 0)  # indeterminate
        self.mini_progress_label.setText("В очереди…")

    def unlock_after_send(self, succeeded):
        """Undoes set_locked_for_send() once a batch finishes, so the row
        is interactive again instead of staying locked until the whole
        window is closed (per user request 2026-08-25 - a per-printer
        failure, e.g. not enough memory on that specific printer, should
        be retryable from the same window instead of failing/blocking the
        whole send). Failed rows stay checked so the very next click on
        Загрузить/Загрузить и запустить resends just those; succeeded ones
        get unchecked so a retry doesn't accidentally resend them too -
        PickerWindow._render_list() (called right after this) decides
        actual visibility from the filters as normal."""
        self.checkbox.setEnabled(True)
        self.rec_checkbox.setEnabled(True)
        self.mini_progress_widget.setVisible(False)
        if succeeded:
            self.checkbox.setChecked(False)

    def set_mini_progress(self, phase, percent, error_reason=None):
        if phase == "error":
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress.setStyleSheet("QProgressBar::chunk { background: %s; }" % COLOR_RED)
            self.mini_progress_label.setText(ERROR_REASON_LABELS.get(error_reason, "Ошибка"))
            return
        self.mini_progress.setStyleSheet("")
        if phase == "done":
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress_label.setText("Готово")
            return
        if percent is None:
            self.mini_progress.setRange(0, 0)
        else:
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(max(4, min(100, int(percent))))
        self.mini_progress_label.setText(TARGET_PHASE_LABELS.get(phase, phase))


class PickerWindow(QMainWindow):
    """One per captured file - the desktop replacement for the old
    PAGE_HTML page. file_path/filename/machine_name are known up front
    (no PENDING/id indirection needed any more - this window IS the state,
    there's no HTTP boundary between it and own_manager's own backend
    functions any more)."""

    _progress_signal = Signal(str, object, list)   # phase, percent(float|None), targets(list[dict])
    _printers_signal = Signal(list, str)           # printers, error message ("" if ok)

    def __init__(self, file_path, filename, machine_name):
        super().__init__()
        self.file_path = file_path
        self.filename = filename
        self.machine_name = (machine_name or "").strip() or None
        self.rows = {}       # printer_id -> PrinterRowWidget
        self.sending = False
        self._loaded_once = False

        self.setWindowTitle("Network sending — %s" % filename)
        self.resize(760, 820)

        central = QWidget()
        central.setObjectName("pickerCentral")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(8)

        # Fixed vertical policy on every label above the form: QLabel's
        # default ("Preferred") is technically allowed to grow past its
        # sizeHint whenever nothing else claims the leftover space,
        # which Qt was doing here - splitting the window's extra height
        # evenly between eyebrow/heading/loading_label into visible gaps.
        # Fixed rules that out unconditionally, so form_widget's own
        # stretch=1 below is the *only* thing that can ever claim leftover
        # vertical space, in every state (loading/error/loaded).
        eyebrow = QLabel("SCALEX LAN MANAGER · NETWORK SENDING")
        eyebrow.setObjectName("eyebrowLabel")
        eyebrow.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        root.addWidget(eyebrow)
        heading = QLabel("Куда отправить файл?")
        heading.setObjectName("headingLabel")
        heading.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        root.addWidget(heading)

        self.loading_label = QLabel("Загружаю список принтеров с ScaleX…")
        self.loading_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.loading_label.setWordWrap(True)
        root.addWidget(self.loading_label)

        self.form_widget = QWidget()
        form = QVBoxLayout(self.form_widget)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.form_widget.setVisible(False)
        self.form_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        root.addWidget(self.form_widget, 1)

        form.addWidget(self._field_label("Имя файла (можно изменить перед отправкой)"))
        self.filename_edit = QLineEdit(filename)
        form.addWidget(self.filename_edit)

        form.addWidget(self._field_label("Поиск принтера"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("имя, IP, модель…")
        self.search_edit.textChanged.connect(self._render_list)
        form.addWidget(self.search_edit)

        self.machine_notice = QLabel()
        self.machine_notice.setObjectName("machineNotice")
        self.machine_notice.setVisible(False)
        form.addWidget(self.machine_notice)

        filters_row = QHBoxLayout()
        self.online_only_cb = QCheckBox("Показывать включённые")
        self.online_only_cb.setChecked(True)
        self.online_only_cb.toggled.connect(self._render_list)
        self.hide_busy_cb = QCheckBox("Скрывать занятые")
        self.hide_busy_cb.setChecked(True)
        self.hide_busy_cb.toggled.connect(self._render_list)
        self.match_only_cb = QCheckBox("Подходит под файл")
        self.match_only_cb.setChecked(True)
        self.match_only_cb.toggled.connect(self._render_list)
        self.match_only_cb.setVisible(False)
        filters_row.addWidget(self.online_only_cb)
        filters_row.addWidget(self.hide_busy_cb)
        filters_row.addWidget(self.match_only_cb)
        filters_row.addStretch(1)
        form.addLayout(filters_row)

        toolbar_row = QHBoxLayout()
        select_all_btn = QPushButton("Выбрать все видимые")
        select_all_btn.clicked.connect(self._select_all_visible)
        clear_all_btn = QPushButton("Снять всё")
        clear_all_btn.clicked.connect(self._clear_all)
        toolbar_row.addWidget(select_all_btn)
        toolbar_row.addWidget(clear_all_btn)
        toolbar_row.addStretch(1)
        self.selected_count_label = QLabel("Выбрано: 0")
        self.selected_count_label.setObjectName("selectedCountLabel")
        toolbar_row.addWidget(self.selected_count_label)
        self.toolbar_row = toolbar_row
        form.addLayout(toolbar_row)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_contents = QWidget()
        self.scroll_contents.setObjectName("pickerScrollContents")
        self.list_layout = QVBoxLayout(self.scroll_contents)
        self.list_layout.setSpacing(6)
        self.list_layout.addStretch(1)  # keeps rows top-aligned as they're added before this
        self.scroll_area.setWidget(self.scroll_contents)
        form.addWidget(self.scroll_area, 1)

        actions_row = QHBoxLayout()
        actions_row.addStretch(1)
        self.close_btn = QPushButton("Закрыть окно")
        self.close_btn.clicked.connect(self.close)
        self.close_btn.setVisible(False)
        # Two explicit buttons instead of a "start print" checkbox modifying
        # one Send button (per user request 2026-08-25) - a dedicated
        # button for "upload and start printing immediately" makes that a
        # deliberate, visible choice rather than something that quietly
        # changes what the main button does depending on a checkbox state
        # you might not notice you left checked from a previous send.
        self.send_and_start_btn = QPushButton("Загрузить и запустить")
        self.send_and_start_btn.setEnabled(False)
        self.send_and_start_btn.clicked.connect(lambda: self._on_send_clicked(start_print=True))
        self.send_btn = QPushButton("Загрузить")
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(lambda: self._on_send_clicked(start_print=False))
        actions_row.addWidget(self.close_btn)
        actions_row.addWidget(self.send_and_start_btn)
        actions_row.addWidget(self.send_btn)
        self.actions_row = actions_row
        form.addLayout(actions_row)

        self.filename_edit.returnPressed.connect(self.search_edit.setFocus)
        self.search_edit.returnPressed.connect(self.send_btn.click)

        self._progress_signal.connect(self._on_progress, Qt.QueuedConnection)
        self._printers_signal.connect(self._on_printers_loaded, Qt.QueuedConnection)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._start_fetch_printers)

        self._start_fetch_printers(initial=True)

    @staticmethod
    def _field_label(text):
        lbl = QLabel(text)
        lbl.setObjectName("fieldLabel")
        return lbl

    # -- printer loading ----------------------------------------------------
    def _start_fetch_printers(self, initial=False):
        def worker():
            try:
                printers = fetch_printers()
                self._printers_signal.emit(printers, "")
            except Exception as e:
                self._printers_signal.emit([], str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _on_printers_loaded(self, printers, error):
        if error and not self._loaded_once:
            self.loading_label.setText(
                "Не удалось получить список принтеров ScaleX (см. лог). Проверьте, что ScaleX запущен и доступен по сети.")
            return
        if error:
            return  # a background refresh failed - keep showing the last known list, try again next tick

        self._loaded_once = True
        self.loading_label.setVisible(False)
        self.form_widget.setVisible(True)

        if self.machine_name:
            self.machine_notice.setText("Нарезано под: %s" % self.machine_name)
            self.machine_notice.setVisible(True)
            self.match_only_cb.setVisible(True)

        for p in printers:
            pid = str(p.get("id"))
            if pid in self.rows:
                self.rows[pid].apply_data(p)
            else:
                # parent=self.scroll_contents matters here, not just as a
                # style choice: a row created with no parent (the default)
                # stays a genuine top-level widget until _render_list()
                # below happens to insertWidget() it into list_layout - and
                # that only happens for rows that pass the CURRENT filter.
                # Most rows fail the default filters (match_only/
                # online_only/hide_busy) on this very first load, so most
                # rows were never inserted at all and stayed parentless -
                # i.e. real, invisible, ever-growing top-level OS windows -
                # for the rest of the picker's life. This was the actual
                # majority contributor to the topLevelWidgets leak (the
                # setParent(None) call removed elsewhere in this file was a
                # second, smaller contributor on top of this one). Giving
                # every row a real parent up front, before filtering ever
                # runs, fixes it regardless of which rows are visible.
                row = PrinterRowWidget(p, parent=self.scroll_contents)
                row.on_selection_changed = self._update_selected_count
                self.rows[pid] = row

        self._render_list()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    # -- filtering/rendering -------------------------------------------------
    def _render_list(self):
        if self.sending:
            return
        query = self.search_edit.text().strip().lower()
        online_only = self.online_only_cb.isChecked()
        hide_busy = self.hide_busy_cb.isChecked()
        match_only = self.match_only_cb.isChecked() and self.match_only_cb.isVisible()

        # remove everything but the trailing stretch, then re-add in sorted,
        # filtered order - cheap (repositioning, not recreating) since rows
        # are persistent widgets.
        #
        # IMPORTANT: only takeAt() here, never setParent(None). takeAt()
        # detaches the widget from the LAYOUT but leaves its Qt parent
        # (scroll_contents) untouched, which is what we want since rows not
        # matching the current filter simply stay an un-laid-out child,
        # invisible, still owned by scroll_contents. Calling setParent(None)
        # on top of that clears the widget's parent entirely, which in Qt
        # promotes it to an independent TOP-LEVEL WIDGET (a real, if
        # invisible, OS window) instead of destroying it - since every row
        # that fails the current filter (search text / online-only /
        # hide-busy / match-only) is never re-inserted, it was orphaned
        # forever as a phantom top-level window every single time
        # _render_list() ran (every 5s printer refresh + every filter
        # keystroke). That's what the topLevelWidgets() diagnostic dump
        # caught: dozens of PrinterRowWidget(visible=False, size=640x480)
        # entries (640x480 is Qt's default size for a parentless widget)
        # accumulating without bound - explaining both the "~5 empty
        # windows" flashes and the picker getting progressively slower to
        # open. Fixed 2026-08-21.
        while self.list_layout.count() > 1:
            self.list_layout.takeAt(0)

        ordered = sorted(self.rows.values(),
                          key=lambda r: (r.printer.get("displayName") or r.printer.get("name") or "").lower())
        for row in ordered:
            visible = row.matches_filters(query, online_only, hide_busy, match_only, self.machine_name)
            row.setVisible(visible)
            if visible:
                self.list_layout.insertWidget(self.list_layout.count() - 1, row)
        self._update_selected_count()

    def _select_all_visible(self):
        for row in self.rows.values():
            if row.isVisible():
                row.checkbox.setChecked(True)

    def _clear_all(self):
        for row in self.rows.values():
            row.checkbox.setChecked(False)

    def _update_selected_count(self):
        n = sum(1 for row in self.rows.values() if row.checkbox.isChecked())
        self.selected_count_label.setText("Выбрано: %d" % n)
        self.send_btn.setEnabled(n > 0 and not self.sending)
        self.send_and_start_btn.setEnabled(n > 0 and not self.sending)

    # -- sending --------------------------------------------------------------
    def _on_send_clicked(self, start_print):
        selected_ids = set()
        targets = []
        for pid, row in self.rows.items():
            if not row.checkbox.isChecked():
                continue
            selected_ids.add(pid)
            apply_rec = row.rec_row.isVisible() and row.rec_checkbox.isChecked()
            targets.append({"printerId": pid, "applyRecommendations": apply_rec})
        if not targets:
            return

        display_name = self.filename_edit.text().strip() or self.filename
        src_ext = os.path.splitext(self.filename)[1]
        if src_ext and not display_name.lower().endswith(src_ext.lower()):
            display_name += src_ext

        self.sending = True
        self._refresh_timer.stop()
        self.filename_edit.setEnabled(False)
        self.search_edit.setEnabled(False)
        self.online_only_cb.setEnabled(False)
        self.hide_busy_cb.setEnabled(False)
        self.match_only_cb.setEnabled(False)
        self.send_and_start_btn.setEnabled(False)
        self.send_btn.setEnabled(False)
        for w in (self.machine_notice,):
            pass  # left visible, harmless

        for pid, row in self.rows.items():
            row.set_locked_for_send(pid in selected_ids)

        logmsg("=== PICKER: sending %s as \"%s\" -> %s (startPrint=%s) ===",
               self.filename, display_name, json.dumps(targets), start_print)

        def report_cb(phase, percent, targets_out):
            self._progress_signal.emit(phase, percent, targets_out)

        send_in_background(self.file_path, targets, display_name=display_name,
                            start_print=start_print, report_cb=report_cb)

    def _on_progress(self, phase, percent, targets_out):
        if not targets_out:
            return
        all_done = True
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if row:
                row.set_mini_progress(t["phase"], t["percent"], t.get("errorReason"))
            if t["phase"] not in ("done", "error"):
                all_done = False
        if all_done:
            self.close_btn.setVisible(True)
            self._enable_retry_for_errors(targets_out)

    def _enable_retry_for_errors(self, targets_out):
        """Once every selected printer has reached a terminal state, let
        failures (insufficient printer memory, a rejected upload, whatever)
        be retried immediately from this same window instead of forcing a
        close-and-reopen-and-reselect-from-scratch (per user request
        2026-08-25). No-op on a fully successful send - that just keeps
        the existing "everything's locked, go press Закрыть окно" ending
        unchanged."""
        if not any(t["phase"] == "error" for t in targets_out):
            return
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if row:
                row.unlock_after_send(succeeded=(t["phase"] != "error"))
        self.sending = False
        self.filename_edit.setEnabled(True)
        self.search_edit.setEnabled(True)
        self.online_only_cb.setEnabled(True)
        self.hide_busy_cb.setEnabled(True)
        self.match_only_cb.setEnabled(True)
        self._refresh_timer.start()
        self._render_list()
        self._update_selected_count()

    def closeEvent(self, event):
        logmsg("=== picker window closed: %s ===", self.filename)
        try:
            _open_windows.remove(self)
        except ValueError:
            pass
        super().closeEvent(event)


_open_windows = []  # keeps PickerWindow instances alive - Qt doesn't hold a Python reference on its own


_TRAILING_HEX_SUFFIX_RE = re.compile(r"_[0-9a-f]{8}$", re.IGNORECASE)


def _clean_display_filename(filename):
    """Both capture paths tack a random 8-hex-char suffix onto the slice
    name for on-disk uniqueness only - handle_client()'s own SaveFile
    request names PENDING files "<label>_<uuid4 hex[:8]>.ctb" so re-sending
    the same job twice can't collide, and slicer_file_watcher()'s files
    (named by ChituManager itself, not us) carry the same kind of suffix.
    Necessary on disk, meaningless clutter in the picker's editable
    filename field/window title, and - if the user never bothers to rename
    it - in what actually gets sent to ScaleX as the file name. Strip it
    for display/default purposes only; the real file on disk (and
    self.file_path, which is what's actually uploaded) keeps its unique
    name regardless."""
    stem, ext = os.path.splitext(filename)
    cleaned = _TRAILING_HEX_SUFFIX_RE.sub("", stem)
    return (cleaned or stem) + ext


def open_picker_window(dest_path):
    """Slot for AppController.file_captured - runs on the GUI thread (the
    signal/slot connection below is queued whenever the emitting thread
    differs from this one, e.g. handle_client()'s background thread), so
    it's safe to create Qt widgets here."""
    filename = _clean_display_filename(os.path.basename(dest_path))
    machine_name = extract_ctb_machine_name(dest_path)
    logmsg("=== OPENING PICKER: %s (machine=%r) ===", filename, machine_name)
    win = PickerWindow(dest_path, filename, machine_name)
    win.show()
    force_window_to_foreground(win)
    _open_windows.append(win)


class AppController(QObject):
    """Lives on the GUI thread; background threads (CHITUBOX protocol
    handler, filesystem watcher) emit into file_captured instead of calling
    open_picker_window directly, so window creation always happens on the
    right thread regardless of which thread captured the file."""
    file_captured = Signal(str)


controller = None  # created in main(), before any background thread starts


# "1a / Send over grid" from the project's icon design pass (2026-08-21) -
# a multi-resolution .ico (16/24/32/48/256, see own_manager_icon.ico) so
# Windows can pick a crisp size for the tray, Alt-Tab, and taskbar instead
# of scaling one flat bitmap.
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "own_manager_icon.ico")


def _make_tray_icon():
    if os.path.isfile(ICON_PATH):
        icon = QIcon(ICON_PATH)
        if not icon.isNull():
            return icon
        logmsg("=== _make_tray_icon: QIcon(%r) loaded but is null, falling back to drawn dot ===", ICON_PATH)
    else:
        logmsg("=== _make_tray_icon: %r not found, falling back to drawn dot ===", ICON_PATH)
    # Fallback so a missing/corrupt icon file never stops the app from
    # starting - just a plain accent-colored dot, same as before this icon
    # existed.
    pm = QPixmap(32, 32)
    pm.fill(Qt.transparent)
    from PySide6.QtGui import QPainter, QBrush
    painter = QPainter(pm)
    painter.setBrush(QBrush(QColor(COLOR_ACCENT)))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(2, 2, 28, 28)
    painter.end()
    return QIcon(pm)


def _manual_send_dialog():
    path, _ = QFileDialog.getOpenFileName(
        None, "Выбрать файл для отправки", "",
        "Слайс-файлы (*.ctb *.goo *.cbddlp *.pwmx);;Все файлы (*)")
    if path:
        open_picker_window(path)


def build_tray_icon(app):
    tray = QSystemTrayIcon(_make_tray_icon())
    tray.setToolTip("own_manager - CHITUBOX -> ScaleX bridge")
    menu = QMenu()
    act_manual = QAction("Отправить файл вручную…")
    act_manual.triggered.connect(_manual_send_dialog)
    act_log = QAction("Открыть лог")
    act_log.triggered.connect(lambda: os.startfile(LOG_PATH))
    act_quit = QAction("Выход")
    act_quit.triggered.connect(app.quit)
    menu.addAction(act_manual)
    menu.addAction(act_log)
    menu.addSeparator()
    menu.addAction(act_quit)
    tray.setContextMenu(menu)
    tray.activated.connect(
        lambda reason: _manual_send_dialog() if reason == QSystemTrayIcon.DoubleClick else None)
    tray.show()
    return tray, menu, (act_manual, act_log, act_quit)  # keep refs alive - PySide6 doesn't on its own

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
                        controller.file_captured.emit(dest)
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

                        controller.file_captured.emit(dest)
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
    global controller

    logmsg("=== own_manager started PID=%d ===", os.getpid())
    logmsg("=== ScaleX: http://%s:%d ===", SCALEX_HOST, SCALEX_PORT)

    # Without this, Windows' taskbar groups every pythonw.exe-hosted window
    # under Python's own generic app identity, and the taskbar BUTTON
    # specifically (unlike the title bar/Alt-Tab icon, which honors Qt's
    # WM_SETICON fine either way) falls back to pythonw.exe's own default
    # icon instead of the one set below via app.setWindowIcon() - confirmed
    # live 2026-08-21 (tray icon correct, picker window's taskbar button
    # still default). Giving the process its own AppUserModelID, before any
    # window exists, is the standard fix - decouples it from the shared
    # "Python" taskbar identity entirely. Must be set before QApplication()
    # creates the first window.
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SolerSport.OwnManager.NetworkSending")
    except Exception as e:
        logmsg("=== SetCurrentProcessExplicitAppUserModelID FAILED (taskbar icon may show default): %s ===", e)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # tray-resident: closing every picker window must not exit the app
    app.setStyleSheet(PICKER_QSS)
    app.setWindowIcon(_make_tray_icon())  # every PickerWindow inherits this (taskbar/Alt-Tab), not just the tray

    controller = AppController()
    controller.file_captured.connect(open_picker_window, Qt.QueuedConnection)

    tray, tray_menu, tray_actions = build_tray_icon(app)  # noqa: F841 - refs kept alive deliberately

    threading.Thread(target=slicer_file_watcher, daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", 0))
    port = listen_sock.getsockname()[1]
    logmsg("=== CHITUBOX protocol listening on 127.0.0.1:%d ===", port)
    listen_sock.listen(5)

    ok = create_shared_memory(SHM_NAME, str(port))
    logmsg("=== shared memory created=%s ===", "yes" if ok else "NO")
    if not ok:
        QMessageBox.critical(None, "own_manager", "Не удалось создать сегмент разделяемой памяти (см. лог). Выход.")
        return 1

    # CHITUBOX only ever opens one persistent connection - handling it in a
    # background thread frees up the main thread for Qt's event loop
    # (app.exec() below blocks here for the process lifetime).
    threading.Thread(target=_chitubox_accept_loop, args=(listen_sock,), daemon=True).start()

    print("own_manager running (Qt). Log: %s" % LOG_PATH)
    print("Picker windows open automatically on each capture; tray icon has manual send / log / exit.")

    try:
        ret = app.exec()
    finally:
        logmsg("=== own_manager exiting ===")
        _logf.close()
    return ret


if __name__ == "__main__":
    sys.exit(main())
