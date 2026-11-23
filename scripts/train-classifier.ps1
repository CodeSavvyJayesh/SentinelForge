# SentinelForge - collect real fix outcomes and train the patch-outcome classifier.
# Usage (from repository root):  .\scripts\train-classifier.ps1
#
# Before running it, in two other windows:
#   1. the backend:  cd backend; .\venv\Scripts\Activate.ps1; python -m uvicorn app.main:app
#   2. Ollama, with the model pulled:  ollama pull qwen2.5-coder:7b
# and have at least one repository scanned, so there are findings to fix.
#
# This asks the running backend for fixes and checks a few at a time, waits for
# them, and stops when there are enough judged fixes to train on (at least 60,
# with 15 of each outcome). Then it trains the model and writes the report.
# It can take hours on a CPU: each fix is one generation by the local model.
# Stop it with Ctrl+C at any time and run it again later; nothing is lost.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$python = Join-Path $backend "venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "backend\venv was not found. Create it first (see docs\development\setup.md)." -ForegroundColor Red
    exit 2
}

Push-Location $backend
try {
    Write-Host "==> Collecting fix outcomes (Ctrl+C to stop; run again to carry on)" -ForegroundColor Cyan
    & $python scripts\collect_patch_outcomes.py auto
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "Not enough judged fixes yet, so nothing was trained. See the message above." -ForegroundColor Yellow
        exit $code
    }
    Write-Host ""
    Write-Host "==> Training" -ForegroundColor Cyan
    & $python scripts\train_patch_classifier.py
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
