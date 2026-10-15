r"""
slm_chitu_send.py - forwards every file CHITUBOX sends over "Network Sending"
to one or more printers on your own ScaleX LAN Manager farm. A native Qt
(PySide6) window pops up for each captured file, letting you rename it,
pick printers (checkboxes), and apply each printer's own recommended
exposure settings - with a tray icon so it's clear it's running and easy to
exit from there.

Run: python slm_chitu_send.py
Requires: PySide6 (pip install PySide6), pycryptodome (optional, see
extract_ctb_machine_name).
Log: C:\slm_chitu_send\slm_chitu_send.log

============================================================================
PACKAGE LAYOUT (split out of the old single-file slm_chitu_send.py)
============================================================================
slm_chitu_send.py        entry point only: `python slm_chitu_send.py`
config                   paths, retention, ScaleX host/port (edit here for your farm)
logs                     logmsg(), the log file handle, credential masking for logs
winapi / shm             ctypes bindings; the QSharedMemory segment CHITUBOX reads
hook_injector            injects goo_hook.dll into CHITUBOX Pro
winfocus                 force a window to the foreground
ctb_file                 CTB header sniffing (machine name of a sliced file)
scalex                   ScaleX LAN Manager HTTP API: printers, warehouse, uploads, polling
composition              matching plate models to warehouse components
sender                   send_in_background(): uploads one file to the chosen printers
printers / theme         printer-state helpers; colors and QSS
printer_row / picker     the picker window (Qt widgets)
app_controller / tray    GUI-thread signals; tray icon and notices
capture                  captured-file handling: goo_hook sidecar, v5 .goo capture
protocol                 CHITUBOX TCP protocol: handle_client, SaveFile request + retry
watchers / cleanup       background folder watchers; old-capture sweep
watchdog                 GUI-thread hang watchdog (dumps stacks into the log)
app                      main(): wires everything together

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
