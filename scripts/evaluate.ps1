# SentinelForge - reproduce the recorded evaluation results (Windows PowerShell).
# Usage (from repository root):  .\scripts\evaluate.ps1
#        .\scripts\evaluate.ps1 -Folder D:\benchmarks
#
# Downloads the two OWASP benchmarks at the exact commits the results were
# recorded against, marks the analyser against each, and compares every result
# with the one in docs\evaluation\results\improved. Nothing in a benchmark is
# built or run: its files are only read.
#
# The benchmarks are kept OUTSIDE this repository (by default in a folder next
# to it), because they are several thousand files of deliberately vulnerable
# code and a scan of this repository should not find them.
#
# Requires: git, and backend\venv with requirements.txt installed (Python 3.12+).

param([string]$Folder = "")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$python = Join-Path $backend "venv\Scripts\python.exe"
$recorded = Join-Path $root "docs\evaluation\results\improved"
if (-not $Folder) {
    $Folder = Join-Path (Split-Path -Parent $root) "sentinelforge-benchmarks"
}

$benchmarks = @(
    @{
        Name   = "BenchmarkJava"
        Url    = "https://github.com/OWASP-Benchmark/BenchmarkJava"
        Commit = "8b67a88d73b2594570fc21150705283de884620b"
        Record = "owasp-java"
        Title  = "OWASP Benchmark for Java"
    },
    @{
        Name   = "BenchmarkPython"
        Url    = "https://github.com/OWASP-Benchmark/BenchmarkPython"
        Commit = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
        Record = "owasp-python"
        Title  = "OWASP Benchmark for Python"
    }
)

function Sync-Benchmark([hashtable]$Benchmark) {
    $target = Join-Path $Folder $Benchmark.Name
    if (-not (Test-Path (Join-Path $target ".git"))) {
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        git -C $target init --quiet
        if ($LASTEXITCODE -ne 0) { throw "git init failed in $target" }
        # The answer key is compared byte for byte, so git must not rewrite
        # line endings on the way to disk.
        git -C $target config core.autocrlf false
        git -C $target remote add origin $Benchmark.Url
    }
    $head = git -C $target rev-parse --verify --quiet HEAD
    if ($head -ne $Benchmark.Commit) {
        Write-Host ("    downloading " + $Benchmark.Name + " at " + $Benchmark.Commit.Substring(0, 12))
        git -C $target fetch --quiet --depth 1 origin $Benchmark.Commit
        if ($LASTEXITCODE -ne 0) { throw "could not download $($Benchmark.Url)" }
        git -C $target -c advice.detachedHead=false checkout --quiet FETCH_HEAD
        if ($LASTEXITCODE -ne 0) { throw "could not check out $($Benchmark.Commit)" }
    }
    $head = git -C $target rev-parse --verify --quiet HEAD
    if ($head -ne $Benchmark.Commit) {
        throw "$target is at $head, not at $($Benchmark.Commit)"
    }
}

if (-not (Test-Path $python)) {
    Write-Host "backend\venv was not found. Create it first (see docs\development\setup.md)." -ForegroundColor Red
    exit 2
}
& $python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "The Python benchmark uses Python 3.12 syntax; backend\venv has an older Python." -ForegroundColor Red
    exit 2
}

$different = @()
$broken = @()

foreach ($benchmark in $benchmarks) {
    Write-Host ""
    Write-Host ("==> " + $benchmark.Title) -ForegroundColor Cyan
    try {
        Sync-Benchmark $benchmark
    } catch {
        Write-Host "    FAILED: $_" -ForegroundColor Red
        $broken += $benchmark.Title
        continue
    }
    $target = Join-Path $Folder $benchmark.Name
    foreach ($split in @("held-out", "development", "all")) {
        $record = Join-Path $recorded ($benchmark.Record + "-" + $split + ".json")
        $label = $benchmark.Title + " (" + $split + ")"
        Push-Location $backend
        try {
            # Only the last line is shown here; run the command by hand for the table.
            $output = & $python -m app.cli evaluate $target --name $benchmark.Title --split $split --check $record
            $code = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($code -eq 0) {
            Write-Host ("    " + $split.PadRight(12) + " REPRODUCED") -ForegroundColor Green
        } elseif ($code -eq 1) {
            Write-Host ("    " + $split.PadRight(12) + " DIFFERENT") -ForegroundColor Red
            $output | Select-Object -Last 15 | ForEach-Object { Write-Host ("      " + $_) }
            $different += $label
        } else {
            Write-Host ("    " + $split.PadRight(12) + " COULD NOT BE MARKED") -ForegroundColor Red
            $broken += $label
        }
    }
}

Write-Host ""
if ($different.Count -eq 0 -and $broken.Count -eq 0) {
    Write-Host "Every recorded result was reproduced." -ForegroundColor Green
    exit 0
}
if ($different.Count -gt 0) {
    Write-Host ("Different from the record: " + ($different -join ", ")) -ForegroundColor Red
}
if ($broken.Count -gt 0) {
    Write-Host ("Could not be run: " + ($broken -join ", ")) -ForegroundColor Red
    exit 2
}
exit 1
