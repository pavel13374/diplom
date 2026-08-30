@echo off
REM ============================================================
REM  SOC SIMULATOR - operator console (live log of both services)
REM ============================================================
REM  This file is deliberately PURE ASCII with CRLF line endings.
REM  cmd.exe reads a .bat in the OEM codepage (cp866 on RU Windows)
REM  line by line. A UTF-8 file with Cyrillic comments gets decoded
REM  byte by byte, some bytes land on &, |, ( or ), the line breaks
REM  apart and cmd tries to run the fragments as commands:
REM      'from' is not recognized as an internal or external command
REM  All human-readable Russian text lives in panel.py, where Python
REM  prints it correctly under chcp 65001.
REM
REM  Previously this file launched launcher.py - a tkinter window.
REM  Logs of the two services sat in SEPARATE tabs, so the order of
REM  events between them could not be reconstructed; text selected
REM  poorly and copied in pieces. Now it is a plain console: one
REM  stream of lines from both services, selectable and copyable.
REM  Old window is still available:  START_PANEL.bat gui
REM ============================================================
setlocal

REM UTF-8 codepage: without it Cyrillic output shows as ?????
chcp 65001 >nul 2>nul

set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
REM Without this, stdout redirected into a pipe is buffered in 8 KiB
REM blocks and the log appears in bursts minutes late.
set PYTHONUNBUFFERED=1

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python not found in PATH. Install Python 3 from python.org and retry.
  pause
  exit /b 1
)

python -c "import flask, requests" 2>nul
if errorlevel 1 (
  echo Installing dependencies from requirements.txt ...
  python -m pip install -r requirements.txt --quiet --disable-pip-version-check
)

REM Optional switches:
REM   set SOC_DEBUG=1         - show DEBUG level
REM   set SOC_LOG_ACCESS=all  - show every HTTP access line (default: 4xx/5xx only)
REM   set SOC_LOG_COLOR=0     - disable colors
python -u panel.py %*

echo.
echo Services stopped. You can close this window.
pause
