param(
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $ProjectRoot "venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Virtual environment Python was not found at $Python"
}

Set-Location $ProjectRoot
& $Python main.py install-service

if ($Start) {
    & $Python main.py start-service
}
