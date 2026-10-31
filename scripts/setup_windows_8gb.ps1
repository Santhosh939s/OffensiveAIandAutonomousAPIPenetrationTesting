# ==============================================================================
# Autonomous API Penetration Testing - Windows 8 GB RAM Automated Setup Script
# Configures the Python 3.8.10 environment without downloading heavy CUDA binaries
# ==============================================================================

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING AGENT" -ForegroundColor Cyan
Write-Host "          PORTABLE WINDOWS (8 GB RAM) ENVIRONMENT SETUP" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

# 1. Check Python Runtime
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Error: Python not found in system PATH. Install Python 3.8.10 64-bit." -ForegroundColor Red
    exit 1
}

$pyVersion = python --version 2>&1
Write-Host "[*] Found Python: $pyVersion" -ForegroundColor Green

# 2. Check Physical Memory
$mem = Get-CimInstance Win32_OperatingSystem
$totalRamGb = [math]::Round($mem.TotalVisibleMemorySize / (1024 * 1024), 2)
$availRamMb = [math]::Round($mem.FreePhysicalMemory / 1024, 2)
Write-Host "[*] Detected Physical RAM: $totalRamGb GB (Available: $availRamMb MB)" -ForegroundColor Yellow

if ($totalRamGb -lt 6.0) {
    Write-Host "[!] Warning: Physical RAM is below 6 GB. Ensure background applications are closed." -ForegroundColor Red
}

# 3. Install Lightweight Dependencies
Write-Host "[*] Verifying / installing lightweight dependencies from requirements.txt..." -ForegroundColor Cyan
python -m pip install --upgrade pip --no-warn-script-location
python -m pip install -r requirements.txt --no-warn-script-location

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Warning: Some dependencies failed to install cleanly. Checking runtime..." -ForegroundColor Yellow
} else {
    Write-Host "[+] Dependencies verified successfully." -ForegroundColor Green
}

# 4. Verify Local Checkpoint Assets
$ckpt200 = "staging_rebuiltv4_training_checkpoints\checkpoint-200\adapter_model.safetensors"
if (Test-Path $ckpt200) {
    $sizeMb = [math]::Round((Get-Item $ckpt200).Length / (1024 * 1024), 2)
    Write-Host "[+] Local RebuiltV4 Checkpoint-200 verified on disk ($sizeMb MB)." -ForegroundColor Green
} else {
    Write-Host "[!] Warning: RebuiltV4 Checkpoint-200 not found at $ckpt200." -ForegroundColor Red
}

# 5. Run Health Check
Write-Host "`n[*] Executing system health check diagnostics..." -ForegroundColor Cyan
python scripts\health_check.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] SETUP COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "[*] To start the live dashboard with vulnerable API lab, execute:" -ForegroundColor White
    Write-Host "    .\scripts\run_optimized_dashboard.ps1" -ForegroundColor Yellow
    Write-Host "    or:" -ForegroundColor White
    Write-Host "    python run_dashboard.py --with-lab --open-browser`n" -ForegroundColor Yellow
} else {
    Write-Host "`n[!] Setup finished with warnings. Review diagnostics above." -ForegroundColor Yellow
}

