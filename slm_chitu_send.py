"""
slm_chitu_send.py - forwards every file CHITUBOX sends over "Network Sending"
to one or more printers on your own ScaleX LAN Manager farm. A native Qt
(PySide6) window pops up for each captured file, letting you rename it,
pick printers (checkboxes), and apply each printer's own recommended
exposure settings - with a tray icon so it's clear it's running and easy to
exit from there.

Run: python slm_chitu_send.py
Requires: PySide6 (pip install PySide6), pycryptodome (optional, see
extract_ctb_machine_name).
Log: C:\\slm_chitu_send\\slm_chitu_send.log

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
ChituManager involvement: slm_chitu_send hijacks the same QSharedMemory
segment CHITUBOX uses to discover "the manager" (create_shared_memory),
so CHITUBOX connects straight to slm_chitu_send's own TCP listener instead of
launching ChituManager at all. CHITUBOX itself (not ChituManager) natively
understands a {"MsgType":"SaveFile","FilePath":"<path>"} request and will
either copy its already-sliced internal file or run a real slice job and
then write exactly that path (confirmed via Ghidra decompile of CHITUBOX
Pro.exe's own ChituManager::saveSliceFile / ChituManager::saveSlicerFileOver,
2026-08-19) - slm_chitu_send asks for this the moment CHITUBOX says it's ready
(its "LoadWindow" ping) and, once the file lands, opens the picker page.

The picker UI has gone through three approaches now, in order: (1) tkinter
(a plain native popup); (2) a page served by slm_chitu_send's own local HTTP
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
    QComboBox,
)

try:
    from Crypto.Cipher import AES  # pip install pycryptodome - see extract_ctb_machine_name
except ImportError:
    AES = None

ROOT_DIR = r"C:\slm_chitu_send\data"
RECEIVED_DIR = os.path.join(ROOT_DIR, "received")  # local backup copy - see RECEIVED_RETENTION_DAYS below
LOG_PATH = os.path.join(ROOT_DIR, "slm_chitu_send.log")

# CTB files routinely run 300MB-900MB each, and every one gets a permanent
# local copy in RECEIVED_DIR - on a farm doing several real sends a day
# that fills the disk within days with no cleanup at all (confirmed live
# 2026-08-26: down to 285MB free after a couple of days, on a 196GB
# drive). RECEIVED_DIR is still genuinely useful for a while (resending,
# checking what actually went out, debugging a failed send), just not
# forever - _cleanup_old_captures() below removes anything older than
# this on a periodic sweep. Bump this if you actually need a longer
# window for re-sends/debugging.
RECEIVED_RETENTION_DAYS = 3
RETENTION_SWEEP_INTERVAL_SEC = 6 * 3600  # a slow-growing folder doesn't need checking often

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
    """Best-effort: returns the file's embedded target-machine name (e.g.
    "ELEGOO Saturn 4 Ultra 16K"), or None if it can't be determined."""
    # 2026-09-08: goo_hook.dll's own custom-built V5.1 output (only ever
    # produced for ELEGOO Jupiter 2 - see goo_hook.c's resolution gate in
    # convert_v3_to_v5) isn't a real CTB file at all, so neither
    # CTB-specific extractor below can find anything in it (different
    # magic, no embedded "Layout and record format..." anchor text) - the
    # "Нарезано под" label was coming back blank for every Jupiter-2
    # capture even though it's fully known. The magic byte alone already
    # identifies it unambiguously.
    try:
        with open(file_path, "rb") as f:
            if f.read(4) == b"V5.1":
                return "ELEGOO Jupiter 2"
    except OSError:
        pass
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

# ---------------------------------------------------------------------------
# CHITUBOX Pro hook auto-injection (2026-09-25) - CreateRemoteThread +
# LoadLibraryW, same technique ChituHook's own inject_by_pid.ps1 used, now
# native here instead of shelling out to a separate script. Needed because a
# static-import patch of CHITUBOX Pro.exe itself (the deploy method used
# before this) gets blocked outright by the app's own Themida file-
# integrity check as of the 2026-09-14 build - see goo_hook.c's module
# comment for the full story. Explicit argtypes/restype throughout: on 64-
# bit Windows, an undeclared ctypes function truncates any HANDLE/LPVOID
# return value to 32 bits, which would silently corrupt every pointer this
# code passes around.
# ---------------------------------------------------------------------------
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID,
    wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.restype = wintypes.BOOL

_PROCESS_ALL_ACCESS = 0x001F0FFF
_MEM_COMMIT = 0x1000
_MEM_RESERVE = 0x2000
_TH32CS_SNAPPROCESS = 0x00000002
_MAX_PATH = 260


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * _MAX_PATH),
    ]


GOO_HOOK_DLL_PATH = r"C:\ChituHook\goo_hook.dll"
CHITUBOX_PRO_EXE_NAME = "CHITUBOX Pro.exe"


def _list_pids_by_exe_name(exe_name):
    """All live PIDs whose process image name matches `exe_name` (case-
    insensitive) - a process snapshot walk, same primitive Task Manager
    itself is built on."""
    snap = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value or not snap:
        return []
    pids = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == exe_name.lower():
                    pids.append(entry.th32ProcessID)
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return pids


def _inject_goo_hook(pid, dll_path):
    """CreateRemoteThread+LoadLibraryW injection of `dll_path` into `pid`.
    Returns (ok, error_message)."""
    hProcess = kernel32.OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
    if not hProcess:
        return False, "OpenProcess failed, err=%d" % ctypes.get_last_error()
    try:
        path_bytes = (dll_path + "\0").encode("utf-16-le")
        remote_mem = kernel32.VirtualAllocEx(
            hProcess, None, len(path_bytes), _MEM_COMMIT | _MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            return False, "VirtualAllocEx failed, err=%d" % ctypes.get_last_error()
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(hProcess, remote_mem, path_bytes, len(path_bytes), ctypes.byref(written)):
            return False, "WriteProcessMemory failed, err=%d" % ctypes.get_last_error()
        k32mod = kernel32.GetModuleHandleW("kernel32.dll")
        load_lib_addr = kernel32.GetProcAddress(k32mod, b"LoadLibraryW")
        if not load_lib_addr:
            return False, "GetProcAddress(LoadLibraryW) failed, err=%d" % ctypes.get_last_error()
        thread_id = wintypes.DWORD(0)
        hThread = kernel32.CreateRemoteThread(
            hProcess, None, 0, load_lib_addr, remote_mem, 0, ctypes.byref(thread_id))
        if not hThread:
            return False, "CreateRemoteThread failed, err=%d" % ctypes.get_last_error()
        try:
            kernel32.WaitForSingleObject(hThread, 10000)
            exit_code = wintypes.DWORD(0)
            kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
        finally:
            kernel32.CloseHandle(hThread)
        if exit_code.value == 0:
            return False, "LoadLibraryW returned NULL in target process"
        return True, None
    finally:
        kernel32.CloseHandle(hProcess)


def chitubox_hook_injector_loop():
    """Background daemon thread - watches for new CHITUBOX Pro.exe processes
    and injects goo_hook.dll into each one exactly once, so the ChituHook
    model-list JSON (composition feature - see read_chitu_hook_model_names)
    is there without the operator ever running a separate injector script
    by hand. A PID is only ever attempted once, success or failure - a
    process that's still starting up when first seen and fails is not worth
    retrying every 5s for its whole lifetime, and a real, repeated failure
    (e.g. a CHITUBOX Pro build whose Themida protection tightens further)
    should show up once in the log per launch, not spam it forever. Skips
    entirely, once, if goo_hook.dll isn't present (e.g. ChituHook was
    removed from this machine)."""
    if not os.path.isfile(GOO_HOOK_DLL_PATH):
        logmsg("=== chitubox_hook_injector: %s not found, watcher disabled ===", GOO_HOOK_DLL_PATH)
        return
    logmsg("=== chitubox_hook_injector: watching for %s ===", CHITUBOX_PRO_EXE_NAME)
    seen_pids = set()
    while True:
        try:
            live_pids = set(_list_pids_by_exe_name(CHITUBOX_PRO_EXE_NAME))
            seen_pids &= live_pids  # forget PIDs that have since exited
            for pid in live_pids - seen_pids:
                seen_pids.add(pid)
                time.sleep(2)  # let the process clear its own very-early init before we touch it
                ok, err = _inject_goo_hook(pid, GOO_HOOK_DLL_PATH)
                logmsg("=== chitubox_hook_injector: %s pid=%d%s ===",
                       "injected goo_hook.dll into" if ok else "FAILED to inject into",
                       pid, "" if ok else " (%s)" % err)
        except Exception as e:
            logmsg("=== chitubox_hook_injector error: %s ===", e)
        time.sleep(5)


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
    all, and slm_chitu_send (reacting to a background thread's signal) never
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
SCALEX_PORT = 8081
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
def fetch_warehouse_components():
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=10)
    try:
        conn.request("GET", "/api/warehouse")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError("HTTP %d" % resp.status)
        data = json.loads(body.decode("utf-8", "replace"))
        return data.get("components") or []
    finally:
        conn.close()


def save_ctb_composition(file_name, component_quantities):
    """PUT /api/warehouse/ctb-mappings - {file_name, component_quantities:
    [{component_id, quantity}]}. This REPLACES whatever composition ScaleX
    already has for this file name, so callers must only call this with a
    genuinely non-empty component_quantities (see PickerWindow's own
    "matched or don't call this at all" guard) - an accidental empty write
    here would silently wipe out a real composition an operator assigned by
    hand through ScaleX's own UI."""
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=15)
    try:
        body = json.dumps({
            "file_name": file_name,
            "component_quantities": [
                {"component_id": cid, "quantity": qty} for cid, qty in component_quantities
            ],
        }).encode("utf-8")
        conn.request("PUT", "/api/warehouse/ctb-mappings", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp_body = resp.read()
        if resp.status not in (200, 201, 202):
            raise RuntimeError("HTTP %d: %s" % (resp.status, resp_body.decode("utf-8", "replace")[:300]))
    finally:
        conn.close()


def read_chitu_hook_model_names(ctb_path):
    """Looks for ChituHook/goo_hook's own sidecar JSON next to `ctb_path`
    (same directory, same base name, ".json" extension) and returns its flat
    list of original model file names, or None if there's no sidecar / it
    isn't readable JSON. Best-effort and silent: a missing sidecar (hook
    disabled or not installed - true by default as of 2026-09-24, see
    goo_hook.c's InstallHooksThread, FL_InstallHook() is commented out there
    pending isolated verification after an unrelated crash - or just an
    older/manually-saved file) is the normal case, not an error worth
    logging on every single capture."""
    json_path = os.path.splitext(ctb_path)[0] + ".json"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            names = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(names, list):
        return None
    return [str(n) for n in names if n]


def _normalize_composition_key(text):
    """Shared by match_composition_components()'s two sides (model name
    stem, component code) - exact match, but tolerant of formatting noise
    that isn't a real difference: case, and whitespace ANYWHERE in the
    string (not just leading/trailing - confirmed live 2026-09-25, real
    model names came back as "WW-35033 _W_R_A.stl" with a space the
    matching warehouse code "WW-35033_W_R_A" doesn't have, so every model
    on that plate went unmatched under a plain .strip())."""
    return re.sub(r"\s+", "", text).lower()


def match_composition_components(model_names, components):
    """Exact match (case-insensitive, whitespace- and extension-stripped) of
    each model file name against a warehouse component - deliberately NOT
    the substring/fuzzy match ScaleX's own browser code uses (see this
    section's module-level comment), since that only ever surfaces one
    guess. Returns (matched, ambiguous, unmatched):

    - matched = list[(component_dict, quantity)], one entry per distinct,
      UNAMBIGUOUSLY matched component - quantity = how many times it
      appeared in model_names (a plate commonly prints several copies of
      the same part).
    - ambiguous = list[(model_name, candidates, quantity)] for any model
      name whose normalized key matches MORE THAN ONE component - this
      happens when the warehouse has several components under different
      articles/codes that share the exact same name (confirmed live
      2026-09-28). There's no correct automatic choice here - which
      article is "the" target for that name is a warehouse-stock decision,
      not something derivable from the CTB/model data - so these are
      surfaced separately for the operator to resolve instead of silently
      picking whichever component happened to come first in the warehouse
      list (the old behavior - see the picker's composition UI).
    - unmatched = the model names with no match at all, so the picker can
      show the operator what it couldn't place instead of silently
      dropping it.

    Matches against BOTH a component's `code` and `name` fields - live data
    confirmed 2026-09-25 that real STL file names correspond to `name`
    ("WW-35033 _W_R_A"), not the shorter, colon-separated `code`
    ("WW-35033W:RA") real files are never actually named after. Checking
    both keeps this working for any other product family that *does*
    happen to use code-style file names."""
    by_key = {}
    for c in components:
        # 2026-10-02: /api/warehouse also returns soft-deleted components
        # (deletedAt set - 248 of 1867 live), and PUT ctb-mappings answers
        # 404 "Component not found" for them. The WW-35029 wheel family
        # had old deleted records (code WW-35028:*) sharing names with
        # their live replacements, so every plate was flagged "ambiguous"
        # with the deleted record first in the picker - the save then
        # 404'd silently (log only) and ScaleX showed "Состав не назначен".
        if c.get("deletedAt"):
            continue
        for key_field in ("code", "name"):
            key = _normalize_composition_key(c.get(key_field) or "")
            if not key:
                continue
            group = by_key.setdefault(key, [])
            if not any(existing["id"] == c["id"] for existing in group):
                group.append(c)

    counts = {}
    ambiguous_groups = {}  # stem -> {"model_name": str, "candidates": [...], "quantity": int}
    unmatched = []
    for name in model_names:
        stem = _normalize_composition_key(os.path.splitext(name)[0])
        candidates = by_key.get(stem)
        if not candidates:
            unmatched.append(name)
        elif len(candidates) == 1:
            cid = candidates[0]["id"]
            counts[cid] = counts.get(cid, 0) + 1
        else:
            group = ambiguous_groups.setdefault(
                stem, {"model_name": name, "candidates": candidates, "quantity": 0})
            group["quantity"] += 1

    comp_by_id = {c["id"]: c for c in components}
    matched = [(comp_by_id[cid], qty) for cid, qty in counts.items()]
    ambiguous = [(g["model_name"], g["candidates"], g["quantity"]) for g in ambiguous_groups.values()]
    return matched, ambiguous, unmatched


def _composition_item_label(component):
    """'name (арт. code)' for the composition notice - shows the actual
    detected article alongside the name, since confirming *which* article
    got matched is the useful thing to glance at before sending, not just
    that something matched. Falls back to whichever of name/code exists
    when the other is missing, and avoids a redundant "X (арт. X)" when
    they're identical."""
    name = component.get("name")
    code = component.get("code")
    if name and code and name != code:
        return "%s (арт. %s)" % (name, code)
    return name or code or component.get("id") or "?"


def suggest_composition_matches(unmatched_names, components, cutoff=0.85):
    """Display-only "did you mean" for model names that matched no live
    warehouse component: {model_name: component label}. Never used to
    assign anything - which part gets decremented from stock must stay an
    operator decision. Live case (2026-10-02): plates named WW-35042_L_A
    while the warehouse holds WM-35042_L_A (WW vs WM) - exact matching
    rightly refuses that, but the operator should be told why."""
    import difflib
    labels = {}
    for c in components:
        if c.get("deletedAt"):
            continue
        for field in ("code", "name"):
            label = c.get(field)
            key = _normalize_composition_key(label or "")
            if key:
                labels.setdefault(key, label)
    keys = list(labels)

    def tail(key):
        return re.sub(r"^[a-z]+-?", "", key)

    by_tail = {}
    for k in keys:
        by_tail.setdefault(tail(k), []).append(k)

    out = {}
    for name in dict.fromkeys(unmatched_names):
        stem = _normalize_composition_key(os.path.splitext(name)[0])
        # Same number/suffix, different letter prefix first (WW-35042_L_A
        # vs WM-35042_L_A - the typical typo), then plain closeness. Up to
        # 3, not 1: WW-35032_L_A is just as close by edit distance but a
        # different real part, so one silent pick could mislead - show the
        # candidates and let the operator judge.
        same_tail = [k for k in by_tail.get(tail(stem), []) if k != stem] if len(tail(stem)) >= 5 else []
        close = same_tail + [k for k in difflib.get_close_matches(stem, keys, n=3, cutoff=cutoff)
                             if k not in same_tail]
        if close:
            out[name] = [labels[k] for k in close[:3]]
    return out


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
        start_print = SCALEX_START_PRINT
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


def patch_and_upload_single(draft_id, printer_id, patch, auto_start, test_print=False):
    """POST /api/ctb/patch-and-upload {printerId, draftId, patch, autoStart}.
    Single-printer only - it's the only ScaleX endpoint that actually starts
    a print (X-Start-Print/autoStart isn't honoured by the bulk endpoints at
    all, confirmed in app.js), so a multi-printer "start print" send loops
    this call once per target printer. testPrint (ScaleX's own field, see
    forward_to_scalex) is only included when true."""
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=1800)
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
    conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=30)
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
            conn = http.client.HTTPConnection(SCALEX_HOST, SCALEX_PORT, timeout=15)
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
#memoryFitLabel { font-size: 11px; margin-top: 1px; }
#memoryFitLabel[fit="yes"] { color: %(green)s; }
#memoryFitLabel[fit="no"] { color: %(red)s; font-weight: 600; }
#stateLabel[state="ready"] { color: %(green)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="busy"] { color: %(red)s; font-size: 11px; font-weight: 600; }
#stateLabel[state="offline"] { color: %(dim)s; font-size: 11px; font-weight: 600; }
#recSummary { color: %(dim)s; font-size: 11px; }
#miniProgressLabel { color: %(dim)s; font-size: 11px; }
#retryBtn { background: transparent; color: %(red)s; border: 1px solid %(red)s;
    border-radius: 6px; padding: 2px 9px; font-size: 10.5px; font-weight: 600; }
#retryBtn:hover { background: rgba(255, 126, 120, .12); }
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


TARGET_PHASE_LABELS = {
    "queued": "В очереди",
    "uploading": "Загрузка",
    "sending": "Передача",
    "done": "Готово",
    "error": "Ошибка",
}

ERROR_REASON_LABELS = {
    "low_memory": "Недостаточно памяти на принтере",
    "conflict": "Принтер сейчас занят другой задачей",
}

RETRY_COOLDOWN_MS = 800  # see set_mini_progress() below


class PrinterRowWidget(QFrame):
    """One printer card - persists for the printer's whole lifetime in this
    window (created once when first seen, updated in place on every 5s
    refresh) so filtering/searching never has to save-and-restore checkbox
    state the way the old JS page did (it had to destroy+recreate DOM nodes
    on every re-render; a native widget just gets hidden/shown/repositioned
    instead, so nothing needs to remember what was checked)."""

    def __init__(self, printer, parent=None, file_size=None):
        super().__init__(parent)
        self.setObjectName("printerRow")
        self.setCursor(Qt.PointingHandCursor)
        self.printer_id = str(printer.get("id"))
        self.printer = printer
        self.file_size = file_size  # the picker's own file, in bytes - see memory_fit_label below
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
        # Shows up front, for every card, whether THIS file should fit on
        # THIS printer's currently-reported free space - refreshed on the
        # same 5s cycle as everything else in apply_data() below. Replaces
        # relying on select-send-fail-retry to find out (per user request
        # 2026-08-26: that reactive flow was confusing/felt buggy even
        # after the debounce fix). send_in_background's own pre-check
        # right before actually dispatching is left in place as a last-
        # moment safety net - the printer's real free space can still
        # change in the few seconds between a refresh and an actual send.
        self.memory_fit_label = QLabel()
        self.memory_fit_label.setObjectName("memoryFitLabel")
        self.memory_fit_label.setVisible(False)
        names.addWidget(self.name_label)
        names.addWidget(self.meta_label)
        names.addWidget(self.memory_fit_label)
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
        for lbl in (self.name_label, self.meta_label, self.state_label, self.memory_fit_label):
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
        self.retry_btn = QPushButton("Повторить")
        self.retry_btn.setObjectName("retryBtn")
        self.retry_btn.setVisible(False)
        self.retry_btn.clicked.connect(self._on_retry_clicked)
        mini_label_row = QHBoxLayout()
        mini_label_row.setContentsMargins(0, 0, 0, 0)
        mini_label_row.setSpacing(8)
        mini_label_row.addWidget(self.mini_progress_label, 1)
        mini_label_row.addWidget(self.retry_btn)
        mini_wrap = QVBoxLayout()
        mini_wrap.setContentsMargins(24, 2, 0, 0)
        mini_wrap.setSpacing(2)
        mini_wrap.addWidget(self.mini_progress)
        mini_wrap.addLayout(mini_label_row)
        self.mini_progress_widget = QWidget()
        self.mini_progress_widget.setLayout(mini_wrap)
        self.mini_progress_widget.setVisible(False)
        outer.addWidget(self.mini_progress_widget)

        self.on_selection_changed = None  # set by PickerWindow
        self.on_retry_requested = None  # set by PickerWindow
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

    def _on_retry_clicked(self):
        # Belt-and-braces on top of the cooldown in set_mini_progress()
        # below: set_locked_for_send() (called synchronously inside
        # _retry_single, before any network/thread activity) already hides
        # this button, but disabling it here too closes the gap between
        # this click and that happening.
        self.retry_btn.setEnabled(False)
        if self.on_retry_requested:
            self.on_retry_requested(self.printer_id)

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

        fit = printer_memory_fit(printer, self.file_size)
        self.memory_fit_label.setVisible(fit is not None)
        if fit is not None:
            fits, fit_text = fit
            self.memory_fit_label.setText(fit_text)
            self.memory_fit_label.setProperty("fit", "yes" if fits else "no")
            self.memory_fit_label.style().unpolish(self.memory_fit_label)
            self.memory_fit_label.style().polish(self.memory_fit_label)

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
        self.retry_btn.setVisible(False)
        self.mini_progress_widget.setVisible(True)
        self.mini_progress.setRange(0, 0)  # indeterminate
        self.mini_progress_label.setText("В очереди…")

    def unlock_after_send(self, succeeded):
        """Undoes set_locked_for_send() once a row reaches a terminal state
        (per user request 2026-08-25 - a per-printer failure, e.g. not
        enough memory on that specific printer, should be retryable
        without closing/reopening the picker). On success: hide the
        progress row entirely and uncheck, exactly like before this
        existed. On failure: leave the progress row (with its error
        message and the Retry button set_mini_progress just armed) fully
        visible instead of hiding it - that button, not this method, is
        now the primary way to act on the failure, so nothing here should
        make it disappear. Checkbox/rec_checkbox re-enable either way so
        the row isn't stuck locked forever even if the user never clicks
        Retry and instead just wants to deselect it."""
        self.checkbox.setEnabled(True)
        self.rec_checkbox.setEnabled(True)
        if succeeded:
            self.mini_progress_widget.setVisible(False)
            self.checkbox.setChecked(False)

    def _rearm_retry_btn(self):
        # Only matters if the row is still actually showing an error -
        # if it moved on (succeeded on a later retry, got deselected,
        # whatever) in the meantime, retry_btn is already hidden and this
        # is a harmless no-op.
        if self.retry_btn.isVisible():
            self.retry_btn.setEnabled(True)

    def set_mini_progress(self, phase, percent, error_reason=None):
        self.retry_btn.setVisible(phase == "error")
        if phase == "error":
            # Confirmed live 2026-08-25: a memory/conflict pre-check that
            # fails is near-instant (no real network round trip), so
            # without a cooldown the button reappears fast enough that a
            # user tapping it again out of reflex creates a visible rapid
            # show/hide flicker on the whole row ("мигал как ебнутый") -
            # 6+ retries logged inside one second. Keeping it visible (so
            # the error text is readable right away) but disabled for a
            # beat gives a calmer, legible state and stops that loop
            # without making a genuinely-ready retry wait any real time.
            self.retry_btn.setEnabled(False)
            QTimer.singleShot(RETRY_COOLDOWN_MS, self._rearm_retry_btn)
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
        if phase == "queued_prepared":
            # Uploaded, but start was deliberately deferred (printer
            # wasn't operatorPrepared) - registered via ScaleX's own
            # queueIfNotPrepared mechanism instead of starting blind or
            # not starting at all (per user request 2026-08-27). ScaleX
            # itself starts the print once an operator marks the printer
            # prepared - nothing more for slm_chitu_send to do here.
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress_label.setText("Загружено — старт назначен, ждём подтверждения подготовки")
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
    there's no HTTP boundary between it and slm_chitu_send's own backend
    functions any more)."""

    _progress_signal = Signal(str, object, list)   # phase, percent(float|None), targets(list[dict])
    _printers_signal = Signal(list, str)           # printers, error message ("" if ok)
    _retry_signal = Signal(list)                   # targets(list[dict]) - one row's own retry, not the whole-batch state
    _composition_signal = Signal(list, str)        # warehouse components, error message ("" if ok)

    def __init__(self, file_path, filename, machine_name, chitubox_conn=None):
        super().__init__()
        self.file_path = file_path
        self.filename = filename
        self.machine_name = (machine_name or "").strip() or None
        # 2026-09-08 (experimental): the live CHITUBOX TCP connection this
        # capture came from, if any (a _ChituboxConn - thread-safe wrapper,
        # see its own docstring - not a raw socket; None for
        # slicer_file_watcher()'s backstop path, which has no connection at
        # all) - kept only so closeEvent() can try to notify CHITUBOX this
        # window closed. See LOADWINDOW_CLOSE_NOTIFY's comment for why.
        self.chitubox_conn = chitubox_conn
        try:
            self.file_size = os.path.getsize(file_path)
        except OSError:
            self.file_size = None  # memory_fit_label just stays hidden on every row rather than guessing
        # 2026-09-24: ChituHook/goo_hook's per-model sidecar JSON, if one
        # landed next to this capture (see read_chitu_hook_model_names) -
        # empty when the hook is disabled/not installed (its default state
        # as of this writing) or the file was saved before this feature
        # existed. composition_matched/unmatched are filled in once
        # _start_fetch_composition()'s background fetch of ScaleX's
        # warehouse components resolves - see _on_composition_loaded.
        self.model_names = read_chitu_hook_model_names(file_path) or []
        self.composition_matched = []    # list[(component_dict, quantity)]
        self.composition_ambiguous = []  # list[(model_name, candidates, quantity)] - see match_composition_components
        self.composition_unmatched = []  # list[str] - model names with no exact code match
        self.composition_choice_combos = {}  # model_name -> QComboBox, one per ambiguous group (operator's article pick)
        self.rows = {}       # printer_id -> PrinterRowWidget
        self.sending = False
        self._loaded_once = False
        self._last_display_name = None  # set by _on_send_clicked, reused by a single-row retry
        self._last_start_print = False
        self._last_test_print = False

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

        # 2026-09-25 (user request): hidden, not removed - never actually
        # used in practice, but _render_list()/matches_filters() still read
        # self.search_edit.text() (always "" now), so keeping the widget
        # around means no changes needed to that filtering logic or its
        # tests, just nothing visible to type into.
        search_label = self._field_label("Поиск принтера")
        search_label.setVisible(False)
        form.addWidget(search_label)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("имя, IP, модель…")
        self.search_edit.textChanged.connect(self._render_list)
        self.search_edit.setVisible(False)
        form.addWidget(self.search_edit)

        self.machine_notice = QLabel()
        self.machine_notice.setObjectName("machineNotice")
        self.machine_notice.setVisible(False)
        form.addWidget(self.machine_notice)

        # 2026-09-24: composition (ChituHook model list -> ScaleX warehouse
        # components, see match_composition_components) - review-only panel;
        # actually saved to ScaleX in _on_send_clicked, alongside the send
        # itself, not from a separate button (per user request). Hidden
        # entirely unless a ChituHook sidecar was actually found for this
        # capture - see model_names above.
        self.composition_notice = QLabel()
        self.composition_notice.setObjectName("machineNotice")
        self.composition_notice.setWordWrap(True)
        self.composition_notice.setVisible(False)
        form.addWidget(self.composition_notice)

        # 2026-09-28 (user request): one name shared by several warehouse
        # articles has no automatically-correct choice (see
        # match_composition_components' "ambiguous" return) - one combo box
        # per ambiguous model name lets the operator pick the target
        # article. Built lazily in _on_composition_loaded() once the actual
        # ambiguous groups (if any) are known; stays empty/invisible
        # otherwise.
        self.composition_ambiguous_widget = QWidget()
        self.composition_ambiguous_layout = QVBoxLayout(self.composition_ambiguous_widget)
        self.composition_ambiguous_layout.setContentsMargins(0, 0, 0, 0)
        self.composition_ambiguous_layout.setSpacing(4)
        self.composition_ambiguous_widget.setVisible(False)
        form.addWidget(self.composition_ambiguous_widget)

        # 2026-10-02 (user request): ScaleX's own «Тестовая - без учёта
        # склада» flag (X-Test-Print / testPrint) - the print is excluded
        # from stock accounting, so no composition is saved for it either
        # (see _save_composition_in_background).
        self.test_print_cb = QCheckBox("Тестовая печать — без учёта склада (состав не сохраняется)")
        self.test_print_cb.toggled.connect(
            lambda checked: self.composition_ambiguous_widget.setEnabled(not checked))
        form.addWidget(self.test_print_cb)

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

        self.filename_edit.returnPressed.connect(self.send_btn.click)

        self._progress_signal.connect(self._on_progress, Qt.QueuedConnection)
        self._printers_signal.connect(self._on_printers_loaded, Qt.QueuedConnection)
        self._retry_signal.connect(self._on_retry_progress, Qt.QueuedConnection)
        self._composition_signal.connect(self._on_composition_loaded, Qt.QueuedConnection)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._start_fetch_printers)

        self._start_fetch_printers(initial=True)
        if self.model_names:
            self.composition_notice.setText("Состав СТБ: подбираю совпадения по данным ChituHook…")
            self.composition_notice.setVisible(True)
            self._start_fetch_composition()

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
                row = PrinterRowWidget(p, parent=self.scroll_contents, file_size=self.file_size)
                row.on_selection_changed = self._update_selected_count
                row.on_retry_requested = self._retry_single
                self.rows[pid] = row

        self._render_list()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    # -- composition (ChituHook -> ScaleX warehouse components) -------------
    def _start_fetch_composition(self):
        def worker():
            try:
                components = fetch_warehouse_components()
                self._composition_signal.emit(components, "")
            except Exception as e:
                self._composition_signal.emit([], str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _on_composition_loaded(self, components, error):
        if error:
            logmsg("=== COMPOSITION: failed to fetch ScaleX warehouse components: %s ===", error)
            self.composition_notice.setVisible(False)
            return
        self.composition_matched, self.composition_ambiguous, self.composition_unmatched = \
            match_composition_components(self.model_names, components)
        self._rebuild_composition_ambiguous_rows()
        if not self.composition_matched and not self.composition_ambiguous and not self.composition_unmatched:
            self.composition_notice.setVisible(False)
            return
        parts = []
        if self.composition_matched:
            # 2026-09-29 (user request): show the actual detected article
            # per component instead of a generic "this came from ChituHook"
            # caption - the article is the useful thing to glance at here
            # (e.g. to confirm it's the right one before sending), the
            # mechanism explanation is not.
            items = ", ".join(
                "%s×%d" % (_composition_item_label(c), qty)
                for c, qty in self.composition_matched)
            parts.append("Состав СТБ: %s" % items)
        elif not self.composition_ambiguous:
            parts.append("Состав СТБ: ни одна модель с плиты не совпала со складским кодом")
        if self.composition_ambiguous:
            parts.append("Несколько артикулов с одним названием (%d) - выберите целевой артикул ниже:" %
                          len(self.composition_ambiguous))
        if self.composition_unmatched:
            hints = suggest_composition_matches(self.composition_unmatched, components)
            counts = {}
            for n in self.composition_unmatched:
                counts[n] = counts.get(n, 0) + 1
            shown = []
            for n, cnt in counts.items():
                item = n if cnt == 1 else "%s×%d" % (n, cnt)
                if n in hints:
                    item += " (похоже на: %s)" % " / ".join(hints[n])
                shown.append(item)
            parts.append("Без совпадения (%d): %s" % (len(self.composition_unmatched), ", ".join(shown)))
        self.composition_notice.setText("\n".join(parts))
        self.composition_notice.setVisible(True)

    def _rebuild_composition_ambiguous_rows(self):
        """One row per ambiguous match (see match_composition_components):
        a label naming the model + quantity, and a combo box of candidate
        components (same name, different article/code) for the operator to
        pick the target article from. Rebuilt from scratch on every
        composition load (only actually happens once per picker window, but
        cheap and avoids stale rows if that ever changes)."""
        while self.composition_ambiguous_layout.count():
            item = self.composition_ambiguous_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.composition_choice_combos = {}
        for model_name, candidates, quantity in self.composition_ambiguous:
            row = QHBoxLayout()
            label = QLabel("%s ×%d:" % (model_name, quantity))
            row.addWidget(label)
            combo = QComboBox()
            for c in candidates:
                option_label = c.get("code") or c.get("id")
                combo.addItem(str(option_label), c)
            row.addWidget(combo, 1)
            self.composition_choice_combos[model_name] = combo
            row_widget = QWidget()
            row_widget.setLayout(row)
            self.composition_ambiguous_layout.addWidget(row_widget)
        self.composition_ambiguous_widget.setVisible(bool(self.composition_ambiguous))

    def _save_composition_in_background(self, file_name):
        """Fired from _on_send_clicked, alongside the actual file send - see
        this class's own composition_notice comment for why there's no
        separate button. Best-effort: a failure here is logged only, never
        surfaced to the operator or allowed to block/fail the real send,
        since this is supplementary warehouse bookkeeping, not the transfer
        itself. Deliberately does nothing at all when nothing matched -
        save_ctb_composition() REPLACES ScaleX's existing composition for
        this file name, so calling it with an empty list here would silently
        wipe out a real one an operator assigned by hand.

        Ambiguous matches (see match_composition_components) are resolved
        here from whatever article is currently selected in each combo box
        built by _rebuild_composition_ambiguous_rows() - read at send time,
        not at load time, so a last-second change of selection is honored."""
        if self.test_print_cb.isChecked():
            return  # test print: excluded from stock, nothing to record
        counts = {}
        for c, qty in self.composition_matched:
            counts[c["id"]] = counts.get(c["id"], 0) + qty
        for model_name, candidates, quantity in self.composition_ambiguous:
            combo = self.composition_choice_combos.get(model_name)
            chosen = combo.currentData() if combo else candidates[0]
            counts[chosen["id"]] = counts.get(chosen["id"], 0) + quantity
        if not counts:
            return
        quantities = list(counts.items())

        def worker():
            try:
                save_ctb_composition(file_name, quantities)
                logmsg("=== COMPOSITION: saved %d component(s) for %s ===", len(quantities), file_name)
            except Exception as e:
                logmsg("=== COMPOSITION: failed to save for %s: %s ===", file_name, e)
        threading.Thread(target=worker, daemon=True).start()

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
        self._last_display_name = display_name  # reused by a later single-row retry
        self._last_start_print = start_print
        test_print = self.test_print_cb.isChecked()
        self._last_test_print = test_print
        self.test_print_cb.setEnabled(False)  # locked for the send, like the other inputs
        self._save_composition_in_background(display_name)

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
            selected = pid in selected_ids
            # 2026-09-30 (user report: sending to an already-printing
            # printer visually "squished its card into another one"): a row
            # checked before its printer went busy (with "Скрывать занятые"
            # on) gets filtered OUT of list_layout entirely by _render_list
            # - unlaid-out, not just hidden (see that method's own comment
            # on why: avoids a worse phantom-window leak). set_locked_for_send
            # below force-shows it again regardless, so without re-inserting
            # it into the layout first, Qt renders it at a stale/unmanaged
            # position - overlapping whatever row IS actually laid out
            # there. Only ever needed for a selected row that fell out of
            # the list this way; every already-laid-out row is a no-op here.
            if selected and self.list_layout.indexOf(row) == -1:
                self.list_layout.insertWidget(self.list_layout.count() - 1, row)
            row.set_locked_for_send(selected)

        logmsg("=== PICKER: sending %s as \"%s\" -> %s (startPrint=%s) ===",
               self.filename, display_name, json.dumps(targets), start_print)

        def report_cb(phase, percent, targets_out):
            self._progress_signal.emit(phase, percent, targets_out)

        send_in_background(self.file_path, targets, display_name=display_name,
                            start_print=start_print, report_cb=report_cb, test_print=test_print)

    def _on_progress(self, phase, percent, targets_out):
        if not targets_out:
            return
        all_done = True
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if row:
                row.set_mini_progress(t["phase"], t["percent"], t.get("errorReason"))
            if t["phase"] not in ("done", "queued_prepared", "error"):
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

    def _retry_single(self, pid):
        """Wired to every row's on_retry_requested - fires the moment that
        one row's own Retry button is clicked, independent of whether the
        rest of the original batch is still in flight (per user request
        2026-08-25: the row shouldn't have to wait for every other printer
        to finish before it becomes actionable). Reuses whatever filename/
        startPrint the original send used; re-reads applyRecommendations
        fresh off the row in case the user toggled it since. Deliberately
        does NOT touch self.sending or the top-level controls the way a
        full send does - this is a small, single-row side operation that
        can run concurrently with (or standalone from) anything else."""
        row = self.rows.get(pid)
        if not row:
            return
        apply_rec = row.rec_row.isVisible() and row.rec_checkbox.isChecked()
        target = {"printerId": pid, "applyRecommendations": apply_rec}
        display_name = self._last_display_name or self.filename
        start_print = self._last_start_print

        row.set_locked_for_send(True)
        logmsg("=== PICKER: retrying %s -> %s (startPrint=%s) ===", self.filename, pid, start_print)

        def report_cb(phase, percent, targets_out):
            self._retry_signal.emit(targets_out)

        send_in_background(self.file_path, [target], display_name=display_name,
                            start_print=start_print, report_cb=report_cb,
                            test_print=self._last_test_print)

    def _on_retry_progress(self, targets_out):
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if not row:
                continue
            row.set_mini_progress(t["phase"], t["percent"], t.get("errorReason"))
            if t["phase"] in ("done", "queued_prepared"):
                row.unlock_after_send(succeeded=True)
            elif t["phase"] == "error":
                # Leave the progress row (error text + re-armed Retry
                # button, both just set by set_mini_progress above)
                # visible - only re-enable the checkbox so the row isn't
                # otherwise stuck locked if they'd rather deselect it than
                # retry again.
                row.checkbox.setEnabled(True)
                row.rec_checkbox.setEnabled(True)

    def closeEvent(self, event):
        try:
            _open_windows.remove(self)
        except ValueError:
            pass
        logmsg("=== picker window closed: %s (%d other picker window(s) still open) ===",
               self.filename, len(_open_windows))
        # 2026-09-08 (experimental, see LOADWINDOW_CLOSE_NOTIFY's comment):
        # tell CHITUBOX this window is gone, unprompted.
        #
        # 2026-09-08 (code-review fix, finding #5): this used to call
        # .send() directly, right here, on the Qt GUI thread. The
        # connection's socket is a plain blocking socket with no timeout
        # ever set anywhere in this file - if CHITUBOX has stopped
        # servicing it without a clean close (crashed, frozen on a native
        # modal, machine asleep), that send() could block for as long as
        # the OS takes to notice the peer is gone (potentially minutes),
        # freezing the ENTIRE app - every window, the tray icon, all of
        # it - not just this one closing window. Firing it from a
        # throwaway daemon thread instead keeps the GUI thread free no
        # matter how long the send takes; _ChituboxConn.send() is already
        # thread-safe (see its own docstring), so this is safe to do from
        # here without any extra locking on this end.
        #
        # 2026-09-29 (investigating "Network sending sometimes does
        # nothing" report): CHITUBOX's own "MainProgramHandle" is the same
        # across every message regardless of which capture it's tied to -
        # its own network-send UI state looks like a single global
        # Visible/not-visible flag, not one per plate/window. Several
        # PickerWindows can be open at once here (one per captured file),
        # so blindly sending Visible:false when ANY one of them closes
        # could tell CHITUBOX "my send window is gone" while a sibling
        # window from the SAME connection is still genuinely open on
        # screen - plausible way for CHITUBOX's own state to get out of
        # sync with reality and start silently ignoring the next click.
        # Only notify when this was the last open window sharing this
        # exact connection.
        chandle = self.chitubox_conn
        if chandle is not None:
            still_open = any(w.chitubox_conn is chandle for w in _open_windows)
            filename = self.filename
            if still_open:
                logmsg("=== close notify SKIPPED for %s: another picker window on the same "
                       "CHITUBOX connection is still open ===", filename)
            else:
                def _notify():
                    ok = chandle.send(LOADWINDOW_CLOSE_NOTIFY)
                    logmsg("=== %s LoadWindow(Visible:false) close notify for %s ===",
                           "SENT" if ok else "SKIPPED (connection already gone)", filename)

                threading.Thread(target=_notify, daemon=True).start()
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


def open_picker_window(dest_path, chitubox_conn=None):
    """Slot for AppController.file_captured - runs on the GUI thread (the
    signal/slot connection below is queued whenever the emitting thread
    differs from this one, e.g. handle_client()'s background thread), so
    it's safe to create Qt widgets here. chitubox_conn (2026-09-08,
    experimental) is the live CHITUBOX connection this capture came from,
    as a _ChituboxConn (thread-safe wrapper, not a raw socket) - None from
    slicer_file_watcher()'s backstop path, which has none - passed through
    only so the window can notify CHITUBOX when it closes, see
    PickerWindow.closeEvent."""
    filename = _clean_display_filename(os.path.basename(dest_path))
    machine_name = extract_ctb_machine_name(dest_path)
    # 2026-09-29: sibling count logged here too (see closeEvent's own
    # comment) - correlating this against a later "Network sending did
    # nothing" report shows whether CHITUBOX's own send-UI state was
    # already juggling more than one open window at the time.
    logmsg("=== OPENING PICKER: %s (machine=%r, %d other picker window(s) already open) ===",
           filename, machine_name, len(_open_windows))
    win = PickerWindow(dest_path, filename, machine_name, chitubox_conn=chitubox_conn)
    win.show()
    force_window_to_foreground(win)
    _open_windows.append(win)


class AppController(QObject):
    """Lives on the GUI thread; background threads (CHITUBOX protocol
    handler, filesystem watcher) emit into file_captured instead of calling
    open_picker_window directly, so window creation always happens on the
    right thread regardless of which thread captured the file. The second
    argument (2026-09-08, experimental) is the live CHITUBOX connection a
    capture came from, as a _ChituboxConn (thread-safe wrapper - see its
    own docstring), or None (slicer_file_watcher()'s backstop path has no
    connection at all) - see PickerWindow.closeEvent."""
    file_captured = Signal(str, object)


controller = None  # created in main(), before any background thread starts


# "1a / Send over grid" from the project's icon design pass (2026-08-21) -
# a multi-resolution .ico (16/24/32/48/256, see slm_chitu_send_icon.ico) so
# Windows can pick a crisp size for the tray, Alt-Tab, and taskbar instead
# of scaling one flat bitmap.
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "slm_chitu_send_icon.ico")


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
    tray.setToolTip("slm_chitu_send - CHITUBOX -> ScaleX bridge")
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

# 2026-09-09: CHITUBOX resets its own TCP connection to us every ~5-6
# minutes regardless of activity (confirmed live - "handle_client FAILED
# ...: [WinError 10054] ... принудительно разорвал существующее
# подключение", twice, ~5.5 min apart, during an otherwise-idle stretch).
# slm_chitu_send's accept loop handles that fine (new connection, clean
# state) - but a genuinely long slice (a big multi-part plate) that
# outlives that window orphans whatever SaveFile request was in flight:
# handle_client()'s thread dies with the dead connection before CHITUBOX
# ever gets to send its SaveFile reply, even though CHITUBOX itself may
# well keep slicing and finish writing the file to PENDING_DIR anyway -
# there's just nobody left listening on that connection to notice. See
# _pending_dir_watcher() below, added for exactly this - a user-observed,
# not directly logged, failure mode ("на этом сообщении был очень долгий
# слайс").
PENDING_ORPHAN_GRACE_SEC = 120  # deliberately generous - real jobs finish
# their live round-trip in seconds to low tens of seconds per
# slm_chitu_send.log's own timings; this only needs to be comfortably shorter
# than the ~5-6 min reset window and comfortably longer than normal
# variance, not tightly tuned.


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


_V5CONVERT_FLAG_PATH = r"C:\ChituHook\chitu_hook_v5convert.flag"

_JUPITER2_PRINTER_TYPES = ("elegoo jupiter 2",)  # exact (normalized) values
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
    src_json = os.path.splitext(send_path)[0] + ".json"
    if not os.path.isfile(src_json):
        return
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
        os.makedirs(RECEIVED_DIR, exist_ok=True)
        dest = os.path.join(RECEIVED_DIR, os.path.basename(send_path))
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
        controller.file_captured.emit(dest, chandle)
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


def handle_client(conn, addr):
    logmsg("=== CLIENT CONNECTED from %s:%d ===", addr[0], addr[1])
    chandle = _ChituboxConn(conn)  # 2026-09-08 (code-review fix, findings #4/#5) - see its own docstring
    last_request_ts = 0.0
    awaiting_path = None
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
            logmsg("RECV(%d): %s", len(chunk), text[:800])

            label = extract_field(text, '"SliceFileName": "')
            if label:
                slice_label = os.path.splitext(label)[0]

            pt = extract_field(text, '"PrinterType": "')
            if pt:
                printer_type = pt

            # The reply to our own SaveFile request: {"MsgType":"SaveFile","Data":{"SavePath":...}}
            if '"MsgType": "SaveFile"' in text and awaiting_path:
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
                awaiting_path = None

            if '"MsgType": "LoadWindow"' in text and '"WinType"' in text:
                ok = chandle.send(LOADWINDOW_REPLY)
                logmsg("%s (%d bytes) LoadWindow reply", "SENT" if ok else "SEND FAILED", len(LOADWINDOW_REPLY))

                if '"Visible": true' in text:
                    now = time.monotonic()
                    if now - last_request_ts >= REQUEST_COOLDOWN_SEC:
                        last_request_ts = now
                        os.makedirs(PENDING_DIR, exist_ok=True)
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
                        target = os.path.join(PENDING_DIR, "%s_%s%s" % (slice_label, uuid.uuid4().hex[:8], ext))
                        awaiting_path = target
                        request = json.dumps({"MsgType": "SaveFile", "FilePath": target.replace("\\", "/")})
                        chandle.send((request + "\n").encode("utf-8"))
                        logmsg("=== REQUESTED SaveFile: %s ===", target)
                    else:
                        logmsg("  -> Visible:true within cooldown (%.1fs ago), not requesting again",
                               now - last_request_ts)
    finally:
        logmsg("=== CLIENT DISCONNECTED ===")
        chandle.close()


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

                        _wait_for_stable_file(path, max_polls=30)  # up to ~6s

                        try:
                            os.makedirs(RECEIVED_DIR, exist_ok=True)
                            dest = os.path.join(RECEIVED_DIR, os.path.basename(path))
                            shutil.copy2(path, dest)
                            logmsg("=== SLICER FILE CAPTURED: %s -> %s (%d bytes) ===",
                                   path, dest, os.path.getsize(dest))
                            _copy_chitu_hook_sidecar(path, dest)
                        except Exception as e:
                            logmsg("=== SLICER FILE CAPTURE FAILED: %s (%s) ===", path, e)
                            continue

                        controller.file_captured.emit(dest, None)
        except Exception as e:
            logmsg("=== slicer_file_watcher error: %s ===", e)
        time.sleep(POLL_INTERVAL_SEC)


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
    if not os.path.isdir(PENDING_DIR):
        return
    for name in os.listdir(PENDING_DIR):
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
        if not name.lower().endswith(SLICE_EXTENSIONS):
            # 2026-09-25: ChituHook/goo_hook's own <basename>.json sidecar
            # (see read_chitu_hook_model_names) lands right next to its .ctb
            # in this same directory - not a slice file, and this watcher
            # has no live connection to remove it once _capture_and_emit()
            # copies its .ctb sibling into RECEIVED_DIR, so it just sits
            # here until PENDING_ORPHAN_GRACE_SEC and got mistaken for an
            # orphaned capture, opening the picker on the .json itself.
            continue
        path = os.path.join(PENDING_DIR, name)
        if path in seen or not os.path.isfile(path):
            continue
        try:
            age = time.time() - os.path.getmtime(path)
        except OSError:
            continue
        if age < PENDING_ORPHAN_GRACE_SEC:
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
           PENDING_DIR, PENDING_ORPHAN_GRACE_SEC)
    seen = set()
    if os.path.isdir(PENDING_DIR):
        for name in os.listdir(PENDING_DIR):
            seen.add(os.path.join(PENDING_DIR, name))

    while True:
        try:
            _pending_dir_watcher_pass(seen)
        except Exception as e:
            logmsg("=== _pending_dir_watcher error: %s ===", e)
        time.sleep(POLL_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Disk cleanup - RECEIVED_DIR is a real backup of every file ever sent, kept
# around for a while (resending, checking what went out, debugging a failed
# send) but not forever; PENDING_DIR should be near-empty already now that
# handle_client() removes its own staging copies right after use, but this
# also mops up anything left over from before that fix, or from any future
# case where that immediate delete fails. See RECEIVED_RETENTION_DAYS above.
# ---------------------------------------------------------------------------
def _cleanup_old_captures():
    cutoff = time.time() - RECEIVED_RETENTION_DAYS * 86400
    total_removed = 0
    total_freed = 0
    for d in (RECEIVED_DIR, PENDING_DIR):
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
               total_removed, total_freed / (1024 * 1024), RECEIVED_RETENTION_DAYS)


def _received_dir_cleanup_loop():
    while True:
        try:
            _cleanup_old_captures()
        except Exception as e:
            logmsg("=== _received_dir_cleanup_loop error: %s ===", e)
        time.sleep(RETENTION_SWEEP_INTERVAL_SEC)


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


def main():
    global controller

    logmsg("=== slm_chitu_send started PID=%d ===", os.getpid())
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
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SolerSport.SlmChituSend.NetworkSending")
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
    threading.Thread(target=_pending_dir_watcher, daemon=True).start()
    threading.Thread(target=_received_dir_cleanup_loop, daemon=True).start()
    threading.Thread(target=chitubox_hook_injector_loop, daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", 0))
    port = listen_sock.getsockname()[1]
    logmsg("=== CHITUBOX protocol listening on 127.0.0.1:%d ===", port)
    listen_sock.listen(5)

    ok = create_shared_memory(SHM_NAME, str(port))
    logmsg("=== shared memory created=%s ===", "yes" if ok else "NO")
    if not ok:
        QMessageBox.critical(None, "slm_chitu_send", "Не удалось создать сегмент разделяемой памяти (см. лог). Выход.")
        return 1

    # CHITUBOX only ever opens one persistent connection - handling it in a
    # background thread frees up the main thread for Qt's event loop
    # (app.exec() below blocks here for the process lifetime).
    threading.Thread(target=_chitubox_accept_loop, args=(listen_sock,), daemon=True).start()

    print("slm_chitu_send running (Qt). Log: %s" % LOG_PATH)
    print("Picker windows open automatically on each capture; tray icon has manual send / log / exit.")

    try:
        ret = app.exec()
    finally:
        logmsg("=== slm_chitu_send exiting ===")
        _logf.close()
    return ret


if __name__ == "__main__":
    sys.exit(main())
