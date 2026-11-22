@echo off
setlocal
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 -m rcdebug %*
) else (
    python -m rcdebug %*
)
endlocal
