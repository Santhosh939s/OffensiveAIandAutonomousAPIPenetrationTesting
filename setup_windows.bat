@echo off
setlocal

title Autonomous API Penetration Testing - Windows Setup

echo ==============================================================================
echo    OFFENSIVE AI AND AUTONOMOUS API PENETRATION TESTING AGENT
echo                   WINDOWS 1-CLICK SETUP UTILITY
echo ==============================================================================
echo.

where powershell >nul 2>nul
if errorlevel 1 (
    echo [ERROR] PowerShell was not found. Please run setup manually.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_windows.ps1"
if errorlevel 1 (
    echo.
    echo [!] Setup encountered warnings or errors. Check the messages above.
    pause
    exit /b 1
)

echo.
pause
endlocal
