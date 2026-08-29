@echo off
setlocal
cd /d "%~dp0"

rem --- Toolchain paths (adjust if your Lazarus install differs) ---
set "LAZ_ROOT=D:\ut\lazarus"
set "FPC_BIN=%LAZ_ROOT%\fpc\3.2.2\bin\x86_64-win64"
set "FPC=%FPC_BIN%\fpc.exe"

if not exist "%FPC%" set "FPC=fpc"
set "PATH=%FPC_BIN%;%PATH%"

echo Building and running self-tests...
"%FPC%" -Fusrc -FEbin tests\selftest.lpr
if errorlevel 1 exit /b 1
bin\selftest.exe
endlocal
