param(
    [Parameter(Mandatory = $true)]
    [string]$SysmonExe,
    [string]$ConfigPath = "",
    [switch]$AcceptEula
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SysmonExe)) {
    throw "Sysmon executable was not found at $SysmonExe. Download Sysmon from Microsoft Sysinternals first."
}

$Arguments = @("-i")
if ($AcceptEula) {
    $Arguments += "-accepteula"
}
if ($ConfigPath) {
    if (-not (Test-Path $ConfigPath)) {
        throw "Sysmon config was not found at $ConfigPath"
    }
    $Arguments += $ConfigPath
}

Start-Process -FilePath $SysmonExe -ArgumentList $Arguments -Wait -NoNewWindow
Write-Host "Sysmon install command completed."

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $ProjectRoot "venv\Scripts\python.exe"
if (Test-Path $Python) {
    Set-Location $ProjectRoot
    & $Python manage.py doctor --profile production
}
