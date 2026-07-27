@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

echo ============================================================
echo   ОЧИСТКА РЕПОЗИТОРИЯ
echo ============================================================
echo.
echo Убирает из-под контроля версий то, что генерируется само:
echo кэши Python, логи, журнал событий, состояние процесса и
echo web_config.json с боевым токеном.
echo.
echo ФАЙЛЫ НА ДИСКЕ ОСТАЮТСЯ. Меняется только индекс git.
echo Проект продолжит работать как работал.
echo.
pause

git rm -r --cached __pycache__ 2>nul
git rm -r --cached data 2>nul
git rm -r --cached logs 2>nul
git rm -r --cached results 2>nul
git rm -r --cached reports 2>nul
git rm --cached simulator.log 2>nul
git rm --cached .sim_state.json 2>nul
git rm --cached web_config.json 2>nul

echo.
echo ------------------------------------------------------------
echo Готово. Осталось закоммитить:
echo    git add .gitignore web_config.example.json
echo    git commit -m "chore: убрать генерируемые файлы и конфиг с токеном из репозитория"
echo ------------------------------------------------------------
echo.
echo ВАЖНО про токен:
echo   web_config.json больше не отслеживается, но он уже лежит
echo   в истории коммитов. Если проект куда-то выкладывается,
echo   токен нужно отозвать в GitLab и выпустить новый.
echo   Для локальной защиты этого достаточно.
echo.
pause
