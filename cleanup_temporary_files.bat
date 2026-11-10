@echo off
setlocal

echo ==============================================================================
echo    OFFENSIVE AI SYSTEM - TEMPORARY CACHE CLEANUP UTILITY
echo ==============================================================================
echo.
echo [*] Cleaning Python bytecode cache (__pycache__, *.pyc)...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" 2>nul
del /s /q *.pyc 2>nul

echo [*] Cleaning temporary test cache (.pytest_cache)...
if exist .pytest_cache rd /s /q .pytest_cache 2>nul

echo [*] Cleaning process lock PID files...
if exist .agent_services.pid del /f /q .agent_services.pid 2>nul

echo.
echo [!] NOTE: Databases (offensive_ai_evidence.db) and Reports (reports/)
echo     have been strictly PRESERVED to protect your audit evidence.
echo.
echo [+] Temporary cleanup complete!
pause
endlocal
