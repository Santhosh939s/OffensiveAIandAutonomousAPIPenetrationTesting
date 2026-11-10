# ==============================================================================
# Autonomous API Penetration Testing - Windows 64-bit Automated Setup Script
# Configures the local Python environment and verifies offline prerequisites
# ==============================================================================

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING SYSTEM" -ForegroundColor Cyan
Write-Host "          WINDOWS PORTABLE ENVIRONMENT INSTALLATION & SETUP" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python Runtime
Write-Host "[1/5] Checking Python Runtime..." -ForegroundColor Yellow
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] ERROR: Python was not found in your system PATH." -ForegroundColor Red
    Write-Host "    Please download and install Python 3.8 to 3.11 64-bit from:" -ForegroundColor White
    Write-Host "    https://www.python.org/downloads/windows/" -ForegroundColor Cyan
    Write-Host "    IMPORTANT: Check 'Add Python to PATH' during installation!" -ForegroundColor Yellow
    exit 1
}

$pyVer = python -c "import platform; print(platform.python_version())" 2>&1
Write-Host "[+] Python Version: $pyVer (64-bit)" -ForegroundColor Green

$is64 = python -c "import sys; sys.exit(0 if sys.maxsize > 2**32 else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] ERROR: 32-bit Python detected. 64-bit Python is strictly required." -ForegroundColor Red
    exit 1
}

# 2. Check System Memory
Write-Host "`n[2/5] Checking System Memory..." -ForegroundColor Yellow
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $totalRamGb = [math]::Round($osInfo.TotalVisibleMemorySize / (1024 * 1024), 2)
    $availRamMb = [math]::Round($osInfo.FreePhysicalMemory / 1024, 2)
    Write-Host "[+] Total RAM     : $totalRamGb GB" -ForegroundColor Green
    Write-Host "[+] Available RAM : $availRamMb MB" -ForegroundColor Green
    if ($totalRamGb -lt 6.0) {
        Write-Host "[!] WARNING: System has less than 6 GB RAM. Close background apps before running." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[*] Memory detection skipped." -ForegroundColor Gray
}

# 3. Install Python Dependencies
Write-Host "`n[3/5] Installing Python Dependencies from requirements.txt..." -ForegroundColor Yellow
python -m pip install --upgrade pip --no-warn-script-location
python -m pip install -r requirements.txt --no-warn-script-location

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Warning: Some dependencies reported non-zero status. Proceeding to verification..." -ForegroundColor Yellow
} else {
    Write-Host "[+] Dependencies installed successfully." -ForegroundColor Green
}

# 4. Verify Inference Engine
Write-Host "`n[4/5] Checking llama-cli Local Inference Engine..." -ForegroundColor Yellow
$llamaCli = Join-Path $PSScriptRoot "models\bin\llama-cli.exe"
if (Test-Path $llamaCli) {
    Write-Host "[+] Found standalone CPU inference engine at: $llamaCli" -ForegroundColor Green
} else {
    Write-Host "[!] WARNING: llama-cli.exe not found at $llamaCli." -ForegroundColor Red
    Write-Host "    CPU inference will fall back to PATH if llama-cli is installed globally." -ForegroundColor Yellow
}

# 5. Verify Model Artifact Integrity
Write-Host "`n[5/5] Checking Qwen GGUF Model Artifact..." -ForegroundColor Yellow
python scripts\verify_or_download_model.py

$modelVerified = ($LASTEXITCODE -eq 0)

# Run full deployment verification
Write-Host "`n[*] Running final pre-flight deployment verification..." -ForegroundColor Cyan
python deployment\verify_installation.py

Write-Host "`n============================================================================" -ForegroundColor Cyan
if ($modelVerified) {
    Write-Host "   [+] SETUP COMPLETE: SYSTEM IS READY TO LAUNCH!" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "To start the application, simply run:" -ForegroundColor White
    Write-Host "    .\launch.bat" -ForegroundColor Yellow
    Write-Host "or double-click launch.bat in Windows Explorer.`n" -ForegroundColor White
} else {
    Write-Host "   [!] SETUP COMPLETE (MODEL REQUIRED)" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "Please place 'qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf' in the 'models\' folder." -ForegroundColor Yellow
    Write-Host "Then double-click launch.bat to start.`n" -ForegroundColor White
}
