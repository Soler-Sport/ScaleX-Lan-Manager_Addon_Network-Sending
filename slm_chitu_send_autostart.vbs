' Launches slm_chitu_send.py hidden (no console window) at Windows logon.
' Placed in the Startup folder so Windows runs it automatically - see
' README.md "Автозапуск" for how this was installed / how to remove it.
'
' 2026-09-25: uses the interpreter's FULL path, not a bare "pythonw.exe" -
' confirmed live that a bare name resolves through some app-execution-alias
' mechanism on this machine and launches TWO interpreters at once (the
' original cause of the "network sending button randomly doesn't work"
' report: two instances race for the same QSharedMemory segment CHITUBOX
' uses to find "the manager", and only one of them is actually listening).
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\slm_chitu_send"
WshShell.Run """C:\Users\rriva\AppData\Local\Python\pythoncore-3.14-64\pythonw.exe"" slm_chitu_send.py", 0, False
