@echo off
REM Builds goo_hook.dll from this directory's goo_hook.c, linking against
REM the prebuilt qml_probe.obj (its own source, qml_probe.cpp, is Qt-heavy
REM and needs a full Qt include environment to recompile - the checked-in
REM .obj is a pragmatic fallback; recompiling it is not part of this
REM script). Requires MSVC Build Tools (x64) and the CHITUBOX Pro-bundled
REM Qt6 import libraries below - adjust QT_LIB_DIR if yours live elsewhere.
setlocal
cd /d "%~dp0"
set QT_LIB_DIR=C:\Users\rriva\Downloads\qt632\6.3.2\msvc2019_64\lib
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /LD /O2 /W3 /nologo goo_hook.c /link /out:goo_hook.dll qml_probe.obj /LIBPATH:"%QT_LIB_DIR%" Qt6Core.lib Qt6Gui.lib Qt6Qml.lib Qt6Quick.lib
