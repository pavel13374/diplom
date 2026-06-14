@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SOC Simulator - Web Admin

set "PY=python"
where python >nul 2>nul || set "PY=py"
%PY% --version >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python 3 not found in PATH. Install Python and try again.
  pause
  exit /b 1
)

echo ============================================================
echo   SOC Simulator - Web Admin
echo   Installing/updating dependencies (first run may take a bit)...
echo ============================================================
%PY% -m pip install -r requirements.txt --quiet --disable-pip-version-check

echo Opening browser at http://127.0.0.1:8787  (login: admin / 123)
start "" http://127.0.0.1:8787

echo Starting web admin. Keep this window open. Press Ctrl+C to stop.
%PY% webapp.py

echo.
echo Server stopped.
pause
