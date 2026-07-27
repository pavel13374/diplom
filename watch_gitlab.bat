@echo off
setlocal
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
echo Watching real GitLab for YOUR manual actions...
echo Do something in GitLab (commit a secret, push at night, delete files)
echo and watch the Purple Team Console on http://127.0.0.1:8788
echo.
python tools\gitlab_watch.py
pause
