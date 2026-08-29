@echo off
setlocal
cd /d "%~dp0"

rem --- Toolchain paths (adjust if your Lazarus install differs) ---
set "LAZ_ROOT=D:\ut\lazarus"
set "FPC_BIN=%LAZ_ROOT%\fpc\3.2.2\bin\x86_64-win64"
set "LAZBUILD=%LAZ_ROOT%\lazbuild.exe"

if not exist "%LAZBUILD%" set "LAZBUILD=lazbuild"
set "PATH=%FPC_BIN%;%PATH%"

echo Building GUI (Lazarus / LCL)...
"%LAZBUILD%" pegasus_scanner.lpi
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)
echo Done. Output: bin\pegasus_scanner.exe
endlocal
