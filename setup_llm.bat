@echo off
setlocal
REM ====================================================================
REM  Local LLM (Ollama) setup for the SOC simulator.
REM  Default model: qwen2.5:7b-instruct (light, runs on CPU).
REM  Custom model:  setup_llm.bat qwen2.5:7b-instruct
REM ====================================================================
set MODEL=%1
if "%MODEL%"=="" set MODEL=qwen2.5:7b-instruct
set PYTHONUTF8=1

echo.
echo ==== SOC Simulator - local LLM setup ====
echo Model: %MODEL%
echo.

where ollama >nul 2>nul
if %errorlevel%==0 goto have_ollama

echo Ollama not found. Trying to install via winget...
winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
if %errorlevel%==0 goto installed

echo.
echo [!] Auto-install failed. Install Ollama manually:
echo     https://ollama.com/download/windows
echo Then run this file again.
pause
exit /b 1

:installed
echo Ollama installed. You may need to open a NEW terminal window
echo so that the "ollama" command appears in PATH, then re-run this file.

:have_ollama
echo.
echo Starting Ollama service (if not already running)...
start "" ollama serve
timeout /t 3 >nul

echo Pulling model %MODEL% (may take several minutes)...
ollama pull %MODEL%
if not %errorlevel%==0 (
  echo [!] Failed to pull the model. Check internet and model name.
  pause
  exit /b 1
)

echo.
echo Testing integration with the simulator...
python tests\test_llm.py

echo.
echo Done. If the test above shows "Ollama: YES" - the LLM is connected.
echo Model is set in config.py - LLM["model"] = "%MODEL%"
pause
