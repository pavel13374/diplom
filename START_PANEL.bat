@echo off
setlocal
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python not found in PATH. Install Python 3 from python.org and retry.
  pause
  exit /b 1
)

REM ensure web deps for the two sites (the panel launches them)
python -c "import flask, requests" 2>nul
if errorlevel 1 (
  echo Installing Flask + requests ...
  python -m pip install Flask requests urllib3 --quiet --disable-pip-version-check
)

echo Starting SOC Simulator control panel ...
python launcher.py
if errorlevel 1 (
  echo.
  echo [!] The panel exited with an error. If it mentions 'tkinter', your Python
  echo     build is missing Tk. Reinstall Python from python.org with the default
  echo     options ^(tcl/tk included^), or run: python -m pip install tk
  pause
)
