@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SOC Simulator - CLI

set "PY=python"
where python >nul 2>nul || set "PY=py"
%PY% --version >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python 3 not found in PATH. Install Python and try again.
  pause
  exit /b 1
)

%PY% -m pip install -r requirements.txt --quiet --disable-pip-version-check

echo Starting SOC Simulator (console mode). Press Ctrl+C to stop.
%PY% main.py

echo.
echo Simulator stopped.
pause
