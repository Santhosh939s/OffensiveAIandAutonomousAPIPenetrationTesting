# ==============================================================================
# Autonomous API Penetration Testing - Low-Memory Dashboard Launcher
# Optimized for Windows 10/11 laptops with 8 GB RAM and integrated graphics
# ==============================================================================

param (
    [int]$Port = 8088,
    [switch]$WithLab = $true,
    [switch]$OpenBrowser = $true
)

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING AGENT" -ForegroundColor Cyan
Write-Host "           LOW-RESOURCE DASHBOARD RUNNER (PORT $Port)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

# Memory optimization environment flags
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:FLASK_ENV = "production"

# Execute health check quick diagnostic
python scripts\health_check.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Pre-flight health check raised warnings. Proceeding with caution..." -ForegroundColor Yellow
}

$cmdArgs = @("run_dashboard.py", "--port", $Port)
if ($WithLab) {
    $cmdArgs += "--with-lab"
}
if ($OpenBrowser) {
    $cmdArgs += "--open-browser"
}

Write-Host "`n[*] Starting autonomous dashboard server on http://127.0.0.1:$Port..." -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to cleanly stop the dashboard.`n" -ForegroundColor White

python @cmdArgs

