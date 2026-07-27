@echo off
setlocal
set PYTHONUTF8=1
echo ==== PROCESS DEFENSE (stream ingestor) ====
python run_defense.py %*
pause
