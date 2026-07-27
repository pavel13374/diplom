@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1

echo ============================================================
echo   SOC SIMULATOR - unified start (World + Defense)
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python not found in PATH. Install Python 3 and retry.
  pause
  exit /b 1
)

python -c "import flask, requests" 2>nul
if errorlevel 1 (
  echo Installing site dependencies (Flask, requests)...
  python -m pip install Flask requests urllib3 --quiet --disable-pip-version-check
)

echo Starting WORLD console (8787)...
start "SOC World 8787" cmd /k "set PYTHONUTF8=1 && python webapp.py"

echo Starting PURPLE TEAM console (8788)...
start "SOC Purple 8788" cmd /k "set PYTHONUTF8=1 && python console.py"

echo Waiting for servers...
timeout /t 5 >nul
start "" http://127.0.0.1:8787
start "" http://127.0.0.1:8788

echo.
echo ============================================================
echo   Two sites opened:
echo     World  (Environment Console):  http://127.0.0.1:8787   (login admin / 123)
echo     Defense (Purple Team Console): http://127.0.0.1:8788
echo.
echo   On the WORLD site press the green Start button to begin the stream.
echo   Defense reads the stream automatically and shows blue alerts.
echo.
echo   Stop everything: STOP.bat  (or close the two console windows).
echo ============================================================
echo.
pause
