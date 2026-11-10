@echo off
setlocal

title Autonomous API Penetration Testing System - Standalone Launcher

echo ==============================================================================
echo    OFFENSIVE AI AND AUTONOMOUS API PENETRATION TESTING AGENT
echo                  WINDOWS STANDALONE LAUNCHER
echo ==============================================================================

set PYTHONUNBUFFERED=1
set PYTHONDONTWRITEBYTECODE=1
set FLASK_ENV=production

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found in your system PATH.
    echo Please install 64-bit Python 3.8 or higher.
    echo.
    pause
    exit /b 1
)

python launcher.py %*
if errorlevel 1 (
    echo.
    echo [ERROR] Launcher exited with error code %ERRORLEVEL%.
    echo Check logs\launcher.log for details.
    echo.
    pause
    exit /b 1
)

endlocal
