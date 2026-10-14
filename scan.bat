@echo off
REM netscan launcher - double-click this on Windows.
REM Any extra arguments are passed straight through, e.g.
REM   scan-my-lan.bat --cidr 192.168.1.0/24 --ports web
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"

if not defined PY (
  echo.
  echo   Python was not found on this PC.
  echo   Install it from  https://www.python.org/downloads/
  echo   and tick "Add python.exe to PATH" during setup.
  echo.
  pause
  exit /b 1
)

%PY% netscan.py %*
echo.
pause
