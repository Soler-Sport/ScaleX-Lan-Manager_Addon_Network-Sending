import ctypes

from .logs import logmsg
from .winapi import ERROR_ALREADY_EXISTS, FILE_MAP_READ, FILE_MAP_WRITE, INVALID_HANDLE_VALUE, PAGE_READWRITE, kernel32


# ---------------------------------------------------------------------------
# CHITUBOX discovery hijack (QSharedMemory) - so CHITUBOX connects to us
# instead of launching ChituManager. This exact name was found via Ghidra
# decompile + a breakpoint on OpenFileMappingW (see README.md).
# ---------------------------------------------------------------------------
SHM_NAME = "qipc_sharedmemory_ServerPort07a1a6dcfadd97d64f9f7f13063e6345d8b33ce8"


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
