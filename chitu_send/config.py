import os


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


# --- Your own manager (ScaleX LAN Manager, FastAPI/uvicorn) ---
SCALEX_HOST = "192.168.0.118"


SCALEX_PORT = 8081


SCALEX_START_PRINT = False  # queue the transfer only, never auto-start a print


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
