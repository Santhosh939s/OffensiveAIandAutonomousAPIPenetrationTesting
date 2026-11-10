@echo off
setlocal

title Reset Admin Password - Autonomous API Pentest

echo ==============================================================================
echo    OFFENSIVE AI AND AUTONOMOUS API PENETRATION TESTING AGENT
echo                  ADMINISTRATOR PASSWORD RESET TOOL
echo ==============================================================================
echo.

set NEW_PASS=%~1

if "%NEW_PASS%"=="" (
    set /p NEW_PASS="Enter new admin password (or press Enter for 'Cyber@2026!'): "
)

if "%NEW_PASS%"=="" (
    set NEW_PASS=Cyber@2026!
)

echo [*] Resetting password for administrator 'admin'...
python launcher.py --recover-admin admin --new-password "%NEW_PASS%"

if errorlevel 1 (
    echo.
    echo [ERROR] Password reset failed. Please ensure:
    echo   1. Password has at least 10 characters
    echo   2. Contains uppercase, lowercase, numbers, and symbols
    echo   3. Does NOT contain the word 'admin'
    echo.
    pause
    exit /b 1
)

echo.
echo ==============================================================================
echo  [SUCCESS] Admin password successfully updated!
echo  Username: admin
echo  Password: %NEW_PASS%
echo ==============================================================================
echo.
echo You can now log in at: http://127.0.0.1:8088/login
echo.

endlocal

