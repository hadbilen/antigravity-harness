@echo off
REM bin/agy-guard.bat — Windows CMD Launcher for Antigravity Guard
setlocal

set "SCRIPT_DIR=%~dp0"
set "HARNESS_DIR=%SCRIPT_DIR%.."

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python "%HARNESS_DIR%\guard.py" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 "%HARNESS_DIR%\guard.py" %*
    exit /b %ERRORLEVEL%
)

echo Error: Python 3 was not found in PATH.
exit /b 1
