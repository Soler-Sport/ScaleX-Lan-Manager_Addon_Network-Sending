import ctypes
import os
import time
from ctypes import wintypes

from .logs import logmsg
from .winapi import PAGE_READWRITE, _MEM_COMMIT, _MEM_RESERVE, _PROCESSENTRY32W, _PROCESS_ALL_ACCESS, _TH32CS_SNAPPROCESS, kernel32


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
