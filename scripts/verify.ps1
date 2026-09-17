# SentinelForge - run every quality check (Windows PowerShell).
# Usage (from repository root):  .\scripts\verify.ps1
# Requires: backend\venv with requirements-dev.txt installed, frontend\node_modules installed,
#           backend\.env with DATABASE_URL and TEST_DATABASE_URL.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$failed = @()

function Invoke-Step([string]$Name, [string]$Dir, [scriptblock]$Command) {
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    Push-Location $Dir
    try {
        & $Command
        if ($LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
        Write-Host "    OK" -ForegroundColor Green
    } catch {
        Write-Host "    FAILED: $_" -ForegroundColor Red
        $script:failed += $Name
    } finally {
        Pop-Location
    }
}

$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$python = Join-Path $backend "venv\Scripts\python.exe"

Invoke-Step "Backend: ruff lint"          $backend  { & $python -m ruff check . }
Invoke-Step "Backend: ruff format check"  $backend  { & $python -m ruff format --check . }
Invoke-Step "Backend: alembic upgrade"    $backend  { & $python -m alembic upgrade head }
Invoke-Step "Backend: alembic check"      $backend  { & $python -m alembic check }
Invoke-Step "Backend: pytest"             $backend  { & $python -m pytest }
Invoke-Step "Frontend: eslint"            $frontend { npm run lint }
Invoke-Step "Frontend: vitest"            $frontend { npm run test }
Invoke-Step "Frontend: typecheck + build" $frontend { npm run build }

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}
Write-Host ("Failed: " + ($failed -join ", ")) -ForegroundColor Red
exit 1
