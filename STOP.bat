@echo off
setlocal
echo Stopping SOC consoles (World 8787 + Purple 8788)...
taskkill /FI "WINDOWTITLE eq SOC World 8787*" /T /F >nul 2>nul
taskkill /FI "WINDOWTITLE eq SOC Purple 8788*" /T /F >nul 2>nul
echo Done. (If windows remain, close them manually.)
pause
