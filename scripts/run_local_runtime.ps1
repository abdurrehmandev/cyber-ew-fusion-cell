[CmdletBinding()]
param(
    [ValidateSet("start", "test", "doctor", "status", "demo")]
    [string]$Command = "start",

    [ValidateSet("dev", "demo", "offline", "production")]
    [string]$Profile = "dev",

    [switch]$NoDashboard,
    [switch]$NoApi,
    [int]$Duration = 0
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot "venv\Scripts\python.exe"
$cacheRoot = Join-Path $env:LOCALAPPDATA "CyberEWFusionCell"
$runtimeRoot = Join-Path $cacheRoot "runtime"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python environment not found at $python. Recreate it with: python -m venv venv; venv\Scripts\python.exe -m pip install -r requirements.txt"
}

# OneDrive Files On-Demand can block Python package imports. Run a fresh local
# mirror while retaining the OneDrive folder as the editable project source.
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
if (Test-Path -LiteralPath $runtimeRoot) {
    $resolvedCache = [IO.Path]::GetFullPath($cacheRoot)
    $resolvedRuntime = [IO.Path]::GetFullPath($runtimeRoot)
    if (-not $resolvedRuntime.StartsWith($resolvedCache, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace an unexpected runtime location: $resolvedRuntime"
    }
    Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

$runtimeDirectories = @("config", "core", "interfaces", "storage", "utils", "data", "tests", "scripts", "packaging")
foreach ($directory in $runtimeDirectories) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $directory) -Destination $runtimeRoot -Recurse -Force
}

$runtimeFiles = @(
    "main.py", "manage.py", "run_live.py", "run_api.py", "run_dashboard.py",
    "desktop_app.py", "windows_service.py", "test_all.py", "requirements.txt"
)
foreach ($file in $runtimeFiles) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $runtimeRoot -Force
}

Push-Location $runtimeRoot
try {
    # Keep pytest and temporary processing files inside the local runtime. This
    # avoids inheriting a protected temporary folder from elevated sessions.
    $runtimeTemp = Join-Path $runtimeRoot "temp"
    New-Item -ItemType Directory -Path $runtimeTemp -Force | Out-Null
    $env:TEMP = $runtimeTemp
    $env:TMP = $runtimeTemp
    switch ($Command) {
        "start" {
            $arguments = @("run_live.py")
            if ($NoDashboard) { $arguments += "--no-dashboard" }
            if ($NoApi) { $arguments += "--no-api" }
            if ($Duration -gt 0) { $arguments += @("--duration", $Duration.ToString()) }
            & $python @arguments
        }
        "test" { & $python "manage.py" "test" }
        "doctor" { & $python "manage.py" "doctor" "--profile" $Profile }
        "status" { & $python "manage.py" "status" "--profile" $Profile }
        "demo" { & $python "manage.py" "demo" "--profile" $Profile }
    }
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
