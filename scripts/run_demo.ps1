param(
    [ValidateSet("dev", "demo", "offline", "production")]
    [string]$Profile = "production"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $ProjectRoot "venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Virtual environment Python was not found at $Python"
}

Set-Location $ProjectRoot
& $Python manage.py demo --profile $Profile
Start-Process "http://127.0.0.1:8501"
