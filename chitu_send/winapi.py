import ctypes
from ctypes import wintypes


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


user32 = ctypes.WinDLL("user32", use_last_error=True)


user32.SetForegroundWindow.argtypes = [wintypes.HWND]


user32.SetForegroundWindow.restype = wintypes.BOOL


user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.LPVOID, wintypes.UINT]


user32.SystemParametersInfoW.restype = wintypes.BOOL


user32.keybd_event.argtypes = [wintypes.BYTE, wintypes.BYTE, wintypes.DWORD, ctypes.c_void_p]


user32.keybd_event.restype = None
