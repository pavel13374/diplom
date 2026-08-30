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

:: Ставим ИМЕННО requirements.txt, а не свой короткий список.
:: Раньше здесь стояло "pip install Flask requests urllib3": на чистой машине
:: стенд поднимался без reportlab (PDF-отчёты) и без numpy/scikit-learn
:: (research/, обучение модели), причём молча — пользователь узнавал об этом
:: только когда кнопка отчёта отдавала HTML вместо PDF.
python -c "import flask, requests" 2>nul
if errorlevel 1 (
  echo Installing dependencies from requirements.txt...
  python -m pip install -r requirements.txt --quiet --disable-pip-version-check
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
:: Пароль НЕ печатается здесь: он либо задан в SOC_ADMIN_PASS, либо
:: генерируется при старте и печатается в окне соответствующей консоли.
:: Раньше тут стояло "(login admin / 123)" — учётные данные, которых в коде
:: давно нет: пользователь вводил их, получал отказ и решал, что стенд сломан.
echo     World  (Environment Console):  http://127.0.0.1:8787
echo     Defense (Purple Team Console): http://127.0.0.1:8788
echo.
echo   Login: admin. Password: SOC_ADMIN_PASS, or the generated one printed
echo   in each console window at startup.
echo.
echo   On the WORLD site press the green Start button to begin the stream.
echo   Defense reads the stream automatically and shows blue alerts.
echo.
echo   Stop everything: STOP.bat  (or close the two console windows).
echo ============================================================
echo.
pause
