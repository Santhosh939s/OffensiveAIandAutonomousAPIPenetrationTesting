@echo off
setlocal

title Autonomous API Penetration Testing System - Clean Shutdown

echo ==============================================================================
echo    OFFENSIVE AI AND AUTONOMOUS API PENETRATION TESTING AGENT
echo                  CLEAN SHUTDOWN UTILITY
echo ==============================================================================

if exist .agent_services.pid (
    echo [*] Stopping services from .agent_services.pid...
    python -c "import os, json; f='.agent_services.pid'; data=json.load(open(f)) if os.path.exists(f) else {}; pid=data.get('pid'); os.system('taskkill /PID ' + str(pid) + ' /F') if pid else None; os.remove(f) if os.path.exists(f) else None"
)

echo [*] Sweeping active listeners on ports 8088 and 5050...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr "127.0.0.1:8088.*LISTENING"') do (
    echo [*] Terminating Dashboard process on port 8088 [PID %%a]...
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr "127.0.0.1:5050.*LISTENING"') do (
    echo [*] Terminating Vulnerable Lab process on port 5050 [PID %%a]...
    taskkill /PID %%a /F >nul 2>&1
)

echo [*] Standalone clean shutdown routine finished.
endlocal
