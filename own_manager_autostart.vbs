' Launches own_manager.py hidden (no console window) at Windows logon.
' Placed in the Startup folder so Windows runs it automatically - see
' README.md "Автозапуск" for how this was installed / how to remove it.
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\rriva\Downloads\own_manager_package"
WshShell.Run "pythonw.exe own_manager.py", 0, False
