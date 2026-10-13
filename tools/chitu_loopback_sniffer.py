"""Passive loopback sniffer for the CHITUBOX <-> stock ChituManager TCP chat.

Why: see tools/chitu_proxy_capture.py - the proxy approach rewrites the
shared-memory port and makes CHITUBOX Pro crash at login (fast-fail
0xC0000409), so this one changes NOTHING: it only listens, using a raw socket
with SIO_RCVALL on 127.0.0.1 (the same trick RawCap uses; needs an elevated
process). The stock manager's TCP port is read (read-only) from the same
shared-memory segment CHITUBOX uses, or given with --port.

Logs every payload-carrying segment to and from that port, plus connection
SYN/FIN/RST markers, to data/loopback_capture.log (Password/Cookie masked).
Each segment is deduplicated by (src port, dst port, seq, length) because
loopback capture can report a packet more than once.

Usage (elevated):  python tools/chitu_loopback_sniffer.py [--seconds 1800] [--port N]
"""
import argparse
import ctypes
import datetime
import os
import queue
import re
import socket
import struct
import sys
import threading
import time

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "loopback_capture.log")
_SECRET_RE = re.compile(r'("(?:password|cookie)"\s*:\s*)"(?:[^"\\]|\\.)*(?:"|$)', re.IGNORECASE)
_log_queue = queue.Queue()


def parse_ipv4_tcp(pkt):
    """-> (src_port, dst_port, seq, flags, payload) for an IPv4/TCP packet, else None."""
    if len(pkt) < 40 or pkt[0] >> 4 != 4 or pkt[9] != 6:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total = struct.unpack("!H", pkt[2:4])[0]
    tcp = pkt[ihl:total] if total else pkt[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    data_off = (tcp[12] >> 4) * 4
    return sport, dport, seq, tcp[13], tcp[data_off:]


def mask(text):
    return _SECRET_RE.sub(r'\1"***"', text)


def log(line):
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


def manager_port_from_segment():
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenFileMappingW.restype = wintypes.HANDLE
    k.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k.MapViewOfFile.restype = wintypes.LPVOID
    k.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    name = "qipc_sharedmemory_ServerPort07a1a6dcfadd97d64f9f7f13063e6345d8b33ce8"
    h = k.OpenFileMappingW(0x0004, False, name)  # FILE_MAP_READ only
    if not h:
        return None
    v = k.MapViewOfFile(h, 0x0004, 0, 0, 0)
    return int(ctypes.string_at(v, 16).split(b"\0")[0]) if v else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=1800)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    threading.Thread(target=_writer, daemon=True).start()

    port = args.port or manager_port_from_segment()
    if not port:
        log("=== no manager port: pass --port or start the stock ChituManager first ===")
        time.sleep(0.5)
        return 1
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind(("127.0.0.1", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    s.settimeout(1.0)
    log("=== sniffing loopback TCP to/from stock manager port %d for %ds ===" % (port, args.seconds))
    seen = set()
    end = time.time() + args.seconds
    while time.time() < end:
        try:
            pkt = s.recv(65535)
        except socket.timeout:
            continue
        parsed = parse_ipv4_tcp(pkt)
        if not parsed:
            continue
        sport, dport, seq, flags, payload = parsed
        if port not in (sport, dport):
            continue
        key = (sport, dport, seq, len(payload), flags)
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > 50000:
            seen.clear()
        direction = "CHITUBOX->MANAGER" if dport == port else "MANAGER->CHITUBOX"
        peer = sport if dport == port else dport
        if payload:
            log("%s [client port %d] (%d bytes): %s" % (
                direction, peer, len(payload), mask(payload.decode("utf-8", "replace")).replace("\r", "").strip()))
        elif flags & 0x07:  # FIN/SYN/RST
            names = [n for bit, n in ((0x02, "SYN"), (0x01, "FIN"), (0x04, "RST")) if flags & bit]
            log("%s [client port %d] TCP %s" % (direction, peer, "+".join(names)))
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    log("=== sniffer finished ===")
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
