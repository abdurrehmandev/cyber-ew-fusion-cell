param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $ProjectRoot "venv\Scripts\python.exe"
$PyInstaller = Join-Path $ProjectRoot "venv\Scripts\pyinstaller.exe"

if (-not (Test-Path $Python)) {
    throw "Virtual environment Python was not found at $Python"
}

Set-Location $ProjectRoot
$WorkPath = Join-Path $env:TEMP ("cyber-ew-pyinstaller-build-" + [DateTime]::UtcNow.ToString("yyyyMMddHHmmss"))
$DistPath = Join-Path $ProjectRoot "dist"

function Find-InnoCompiler {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )

    $pathCandidate = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($pathCandidate) {
        $candidates += $pathCandidate.Source
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

if (-not (Test-Path $PyInstaller)) {
    & $Python -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller."
    }
}

& $PyInstaller packaging\cyber_ew_fusion_cell.spec --clean --workpath $WorkPath --distpath $DistPath
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

if (-not $SkipInstaller) {
    $Inno = Find-InnoCompiler
    if ($Inno -and (Test-Path $Inno)) {
        & $Inno packaging\cyber-ew-fusion-cell.iss
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup build failed."
        }
    } else {
        throw "Inno Setup was not found. Install Inno Setup 6 or rerun with -SkipInstaller."
    }
}

Write-Host "Build output: $ProjectRoot\dist"
