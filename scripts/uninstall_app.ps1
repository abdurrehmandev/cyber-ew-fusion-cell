param(
    [string]$InstallDir = "$env:LOCALAPPDATA\CyberEWFusionCell",
    [switch]$KeepData
)

$ErrorActionPreference = "Stop"
$InstallRoot = if (Test-Path $InstallDir) { (Resolve-Path $InstallDir).Path } else { $InstallDir }
$ThisProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "Cyber-EW Fusion Cell Uninstaller"
Write-Host "--------------------------------"

$Python = Join-Path $ThisProjectRoot "venv\Scripts\python.exe"
if (Test-Path $Python) {
    Set-Location $ThisProjectRoot
    & $Python manage.py stop
}

$TaskScript = Join-Path $ThisProjectRoot "scripts\uninstall_windows_task.ps1"
if (Test-Path $TaskScript) {
    & $TaskScript
}

$ProgramsDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Cyber-EW Fusion Cell"
if (Test-Path $ProgramsDir) {
    Remove-Item -LiteralPath $ProgramsDir -Recurse -Force
    Write-Host "Removed Start Menu shortcuts."
}

$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Cyber-EW Fusion Cell.lnk"
if (Test-Path $DesktopShortcut) {
    Remove-Item -LiteralPath $DesktopShortcut -Force
    Write-Host "Removed Desktop shortcut."
}

if ($ThisProjectRoot -ne $InstallRoot) {
    if ($KeepData) {
        $DataDir = Join-Path $InstallRoot "data"
        $BackupDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "CyberEWFusionCell-DataBackup"
        if (Test-Path $DataDir) {
            Copy-Item -LiteralPath $DataDir -Destination $BackupDir -Recurse -Force
            Write-Host "Copied data backup to $BackupDir"
        }
    }

    if (Test-Path $InstallRoot) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
        Write-Host "Removed installed app directory: $InstallRoot"
    }
} else {
    Write-Host "Uninstaller is running from the source project folder, so project files were not removed."
}

Write-Host "Uninstall complete."
