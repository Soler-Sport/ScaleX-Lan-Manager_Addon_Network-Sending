"""Transparent proxy between CHITUBOX Pro and the STOCK ChituManager - records
the whole conversation so it can be compared with what slm_chitu_send does.

Why: CHITUBOX silently drops ~15% of the SaveFile requests slm_chitu_send
sends it (see chitu_send/protocol.py, _request_save_with_retry), yet the stock
ChituManager works fine, so it must be doing something we don't. Neither
program logs the protocol, so we watch it on the wire.

How it works: CHITUBOX finds "the manager" through the named shared-memory
segment SHM_NAME, which holds the manager's TCP port as ASCII. With the stock
ChituManager running (it creates that segment), this tool opens the segment,
remembers the real port (and checks it answers), starts its own listener and
writes ITS port into the segment. CHITUBOX then connects to the proxy, which
connects on to the real ChituManager and copies bytes both ways. The bug being
chased depends on millisecond timing, so each chunk is forwarded FIRST and
only then queued for a separate writer thread to log; TCP_NODELAY is on. The
original port is restored on exit (only if the segment still holds ours).

Usage (CHITUBOX must connect AFTER the swap - start CHITUBOX, wait for the
stock ChituManager to appear, run this, THEN click "Network sending"; if
CHITUBOX already connected, restart CHITUBOX once while this keeps running):
    python tools/chitu_proxy_capture.py [--seconds 900] [--shm-name NAME]
Log: data/proxy_capture.log (Password/Cookie values are masked).
"""
import argparse
import atexit
import ctypes
import datetime
import os
import queue
import re
import socket
import sys
import threading
import time
from ctypes import wintypes

SHM_NAME = "qipc_sharedmemory_ServerPort07a1a6dcfadd97d64f9f7f13063e6345d8b33ce8"
FILE_MAP_ALL_ACCESS = 0x000F001F
LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "proxy_capture.log")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenFileMappingW.restype = wintypes.HANDLE
kernel32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.MapViewOfFile.restype = wintypes.LPVOID
kernel32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
kernel32.UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

# Also masks a value cut off by the end of the chunk (no closing quote yet).
_SECRET_RE = re.compile(r'("(?:password|cookie)"\s*:\s*)"(?:[^"\\]|\\.)*(?:"|$)', re.IGNORECASE)
_log_queue = queue.Queue()


def log(line):
    """Never blocks the proxy: the stamp is taken now, the file write happens
    on the writer thread."""
    stamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    _log_queue.put("[%s] %s" % (stamp, line))


def _writer():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8", newline="") as f:
        while True:
            item = _log_queue.get()
            if item is None:
                return
            f.write(item + "\r\n")
            f.flush()
            print(item[:200])


def open_segment(name):
    handle = kernel32.OpenFileMappingW(FILE_MAP_ALL_ACCESS, False, name)
    if not handle:
        return None, None
    view = kernel32.MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, 0)
    if not view:
        kernel32.CloseHandle(handle)
        return None, None
    return handle, view


def read_port(view):
    raw = ctypes.string_at(view, 32)
    return int(raw.split(b"\0")[0].decode("ascii")), raw


def write_port(view, port):
    data = str(port).encode("ascii") + b"\0"
    ctypes.memmove(view, data, len(data))


def pump(src, dst, label):
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)  # forward first - logging must not delay the wire
            text = _SECRET_RE.sub(r'\1"***"', chunk.decode("utf-8", "replace"))
            log("%s (%d bytes): %s" % (label, len(chunk), text.replace("\r", "").strip()))
    except OSError as e:
        log("%s pump ended: %s" % (label, e))
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def serve(listener, real_port):
    while True:
        try:
            client, addr = listener.accept()
        except OSError:
            return
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log("=== CHITUBOX connected from %s:%d -> forwarding to real manager on %d ===" % (addr[0], addr[1], real_port))
        try:
            upstream = socket.create_connection(("127.0.0.1", real_port), timeout=5)
            upstream.settimeout(None)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            log("=== could not reach the real manager on %d: %s ===" % (real_port, e))
            client.close()
            continue
        threading.Thread(target=pump, args=(client, upstream, "CHITUBOX->MANAGER"), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, "MANAGER->CHITUBOX"), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=900, help="how long to keep capturing")
    ap.add_argument("--shm-name", default=SHM_NAME)
    ap.add_argument("--wait", type=int, default=120, help="how long to wait for the manager's segment to appear")
    args = ap.parse_args()
    threading.Thread(target=_writer, daemon=True).start()

    log("=== waiting for the manager's shared-memory segment (up to %ds) ===" % args.wait)
    handle = view = None
    deadline = time.time() + args.wait
    while time.time() < deadline:
        handle, view = open_segment(args.shm_name)
        if view:
            break
        time.sleep(1)
    if not view:
        log("=== segment not found - is the stock ChituManager running (and slm_chitu_send stopped)? ===")
        time.sleep(0.5)
        return 1
    real_port, raw = read_port(view)
    log("=== segment found: manager port %d (raw bytes %r) ===" % (real_port, raw))
    # A crashed earlier run may have left ITS dead proxy port in the segment.
    # Checked WITHOUT connecting (a connect+close would look like a CHITUBOX
    # coming and going to the stock manager): if we can bind the port, nobody
    # is listening on it.
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", real_port))
        free = True
    except OSError:
        free = False
    finally:
        probe.close()
    if free:
        log("=== nobody listens on port %d - stale segment? Restart ChituManager, aborting ===" % real_port)
        time.sleep(0.5)
        return 1

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    proxy_port = listener.getsockname()[1]
    restored = []

    def restore():
        if restored:
            return
        restored.append(True)
        try:
            if read_port(view)[0] == proxy_port:  # don't clobber a manager that restarted meanwhile
                write_port(view, real_port)
                log("=== restored segment to port %d, capture finished ===" % real_port)
            else:
                log("=== segment no longer holds the proxy port - left alone ===")
        except Exception as e:
            log("=== restore failed: %s ===" % e)
        time.sleep(0.3)

    atexit.register(restore)
    try:
        write_port(view, proxy_port)
        log("=== proxy listening on %d, segment now points there ===" % proxy_port)
        threading.Thread(target=serve, args=(listener, real_port), daemon=True).start()
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        restore()
        listener.close()
        kernel32.UnmapViewOfFile(view)
        kernel32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
