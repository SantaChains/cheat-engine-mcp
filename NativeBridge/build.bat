@echo off
REM Build ce_mcp_tcp.dll for Cheat Engine MCP Bridge
REM
REM Usage:
REM   build.bat              - x64 Release via MinGW (default, one-shot, no env vars)
REM   build.bat mingw        - same as default
REM   build.bat msvc         - x64 Release via MSVC (requires cl.exe in PATH or vcvars)
REM   build.bat x86          - x86 Release via MSVC (no i686 MinGW toolchain on this machine)
REM
REM Outputs: bin\x64\ce_mcp_tcp_x64.dll / bin\x86\ce_mcp_tcp_x86.dll
REM
REM MinGW one-liner (works from Git Bash directly, no INCLUDE/LIB dance):
REM   gcc -shared -O2 -s -static ce_mcp_tcp.c -o bin/x64/ce_mcp_tcp_x64.dll -lws2_32 -luser32 -lkernel32
REM Verify: objdump -p <dll> | grep "DLL Name"  -> must show NO libgcc/libwinpthread.

setlocal

set MODE=%1
if "%MODE%"=="" set MODE=mingw

if /i "%MODE%"=="mingw" goto mingw
if /i "%MODE%"=="msvc"  goto msvc
if /i "%MODE%"=="x86"   goto msvc_x86
echo Unknown mode: %MODE%
exit /b 1

:mingw
set GCC=D:\langcode\gcc\mingw64\bin\gcc.exe
if not exist %GCC% (
    echo MinGW not found at %GCC% - install winlibs/MSYS2 gcc or use: build.bat msvc
    exit /b 1
)
if not exist bin\x64 mkdir bin\x64
echo Building ce_mcp_tcp.dll (x64, MinGW gcc)...
%GCC% -shared -O2 -s -static ^
    -D "WIN32" -D "NDEBUG" -D "_WINDOWS" -D "_USRDLL" ^
    -D "_CRT_SECURE_NO_WARNINGS" -D "_WINSOCK_DEPRECATED_NO_WARNINGS" ^
    ce_mcp_tcp.c -o bin\x64\ce_mcp_tcp_x64.dll -lws2_32 -luser32 -lkernel32 ^
    -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo SUCCESS: bin\x64\ce_mcp_tcp_x64.dll
goto :eof

:msvc
if not exist bin\x64 mkdir bin\x64
echo Building ce_mcp_tcp.dll (x64, MSVC /MT)...
cl.exe /nologo /O2 /LD /W3 /MT /guard:cf ^
    /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" ^
    /D "_CRT_SECURE_NO_WARNINGS" /D "_WINSOCK_DEPRECATED_NO_WARNINGS" ^
    ce_mcp_tcp.c ^
    ws2_32.lib kernel32.lib user32.lib ^
    /Fe:bin\x64\ce_mcp_tcp_x64.dll ^
    /Fo:bin\x64\ ^
    /link /DLL /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /GUARD:CF
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
del /q bin\x64\*.obj bin\x64\*.exp bin\x64\*.lib 2>nul
echo SUCCESS: bin\x64\ce_mcp_tcp_x64.dll
goto :eof

:msvc_x86
if not exist bin\x86 mkdir bin\x86
echo Building ce_mcp_tcp.dll (x86, MSVC /MT)...
cl.exe /nologo /O2 /LD /W3 /MT /guard:cf ^
    /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" ^
    /D "_CRT_SECURE_NO_WARNINGS" /D "_WINSOCK_DEPRECATED_NO_WARNINGS" ^
    ce_mcp_tcp.c ^
    ws2_32.lib kernel32.lib user32.lib ^
    /Fe:bin\x86\ce_mcp_tcp_x86.dll ^
    /Fo:bin\x86\ ^
    /link /DLL /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /GUARD:CF
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
del /q bin\x86\*.obj bin\x86\*.exp bin\x86\*.lib 2>nul
echo SUCCESS: bin\x86\ce_mcp_tcp_x86.dll
goto :eof
