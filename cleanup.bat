@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   Чистка проекта: attic\ (мусор) и кэши Python
echo ============================================================

REM --- attic: сюда сложено всё лишнее при реорганизации ---
if exist attic (
  rmdir /s /q attic
  echo  [x] attic\  удалена
)

REM --- кэши Python по всему проекту ---
for /d /r %%D in (__pycache__) do if exist "%%D" rmdir /s /q "%%D"
del /s /q *.pyc >nul 2>&1
echo  [x] __pycache__ и *.pyc

REM --- легаси, если ещё осталось ---
for %%F in (expl.md QUICKSTART.md README.md UX_AUDIT.md IMPROVEMENTS_PROMPTS.md PROMPT_FOR_CLAUDE.md run.bat run_cli.bat) do (
  if exist "%%F" ( del /q "%%F" & echo  [x] %%F )
)
if exist docs rmdir /s /q docs & echo  [x] docs\

echo.
echo Готово. Структура проекта:
echo   корень     ? движок и два сайта (webapp, console, launcher)
echo   tools\     ? утилиты (сброс, демо, отчёты, GitLab)
echo   research\  ? ML-эксперименты и датасеты
echo   tests\     ? тесты (запуск: python run_tests.py)
echo Запуск как обычно: START_PANEL.bat
pause
