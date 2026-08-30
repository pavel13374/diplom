@echo off
setlocal
echo Stopping SOC consoles (World 8787 + Purple 8788)...

:: Сначала МЯГКО. Форсированное завершение (/F) не даёт процессам сохранить
:: состояние симуляции, закрыть журнал событий и записать курсор ингеста —
:: то есть теряется хвост прогона и часть событий переигрывается заново.
taskkill /FI "WINDOWTITLE eq SOC World 8787*" /T >nul 2>nul
taskkill /FI "WINDOWTITLE eq SOC Purple 8788*" /T >nul 2>nul
timeout /t 5 >nul

:: Кто не завершился — снимаем принудительно.
taskkill /FI "WINDOWTITLE eq SOC World 8787*" /T /F >nul 2>nul
taskkill /FI "WINDOWTITLE eq SOC Purple 8788*" /T /F >nul 2>nul
echo Done. (If windows remain, close them manually.)
pause
