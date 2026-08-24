param(
    [ValidateSet("dev", "demo", "offline", "production")]
    [string]$Profile = "production",
    [string]$InstallDir = "$env:LOCALAPPDATA\CyberEWFusionCell",
    [switch]$DesktopShortcut,
    [switch]$AutoStart,
    [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

function New-AppShortcut {
    param(
        [string]$ShortcutPath,
        [string]$TargetScript,
        [string]$Arguments = "",
        [string]$WorkingDirectory,
        [string]$Description
    )

    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`" $Arguments"
    $Shortcut.WorkingDirectory = $WorkingDirectory
    $Shortcut.Description = $Description
    $Shortcut.IconLocation = "powershell.exe,0"
    $Shortcut.Save()
}

$SourceRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$InstallRoot = if ($NoCopy) { $SourceRoot.Path } else { $InstallDir }

Write-Host "Cyber-EW Fusion Cell Windows App Installer"
Write-Host "------------------------------------------"
Write-Host "Profile: $Profile"
Write-Host "Install directory: $InstallRoot"

if (-not $NoCopy) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    $ExcludeDirs = @(".git", ".pytest_cache", "__pycache__", "venv_old_broken")
    $ExcludeFiles = @("*.pyc", "*.pyo")

    Get-ChildItem -Path $SourceRoot -Force | Where-Object {
        $ExcludeDirs -notcontains $_.Name
    } | ForEach-Object {
        $Destination = Join-Path $InstallRoot $_.Name
        if ($_.PSIsContainer) {
            robocopy $_.FullName $Destination /E /XD ".git" ".pytest_cache" "__pycache__" "venv_old_broken" /XF "*.pyc" "*.pyo" | Out-Null
            if ($LASTEXITCODE -gt 7) {
                throw "Failed copying $($_.FullName) to $Destination"
            }
        } elseif ($ExcludeFiles -notcontains $_.Name) {
            Copy-Item -LiteralPath $_.FullName -Destination $Destination -Force
        }
    }
}

$Python = Join-Path $InstallRoot "venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    Write-Host "Creating virtual environment..."
    python -m venv (Join-Path $InstallRoot "venv")
}

if (-not (Test-Path $Python)) {
    throw "Python virtual environment was not created. Install Python 3.12 and run this installer again."
}

Set-Location $InstallRoot
Write-Host "Installing requirements..."
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

Write-Host "Running deployment doctor..."
& $Python manage.py doctor --profile $Profile

$ProgramsDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Cyber-EW Fusion Cell"
New-Item -ItemType Directory -Force -Path $ProgramsDir | Out-Null

New-AppShortcut `
    -ShortcutPath (Join-Path $ProgramsDir "Cyber-EW Fusion Cell.lnk") `
    -TargetScript (Join-Path $InstallRoot "scripts\open_dashboard.ps1") `
    -Arguments "-Profile $Profile" `
    -WorkingDirectory $InstallRoot `
    -Description "Start Cyber-EW Fusion Cell and open the dashboard."

New-AppShortcut `
    -ShortcutPath (Join-Path $ProgramsDir "Cyber-EW Status.lnk") `
    -TargetScript (Join-Path $InstallRoot "scripts\status_service.ps1") `
    -Arguments "-Profile $Profile" `
    -WorkingDirectory $InstallRoot `
    -Description "Show Cyber-EW service health and deployment report."

New-AppShortcut `
    -ShortcutPath (Join-Path $ProgramsDir "Cyber-EW Demo Scenario.lnk") `
    -TargetScript (Join-Path $InstallRoot "scripts\run_demo.ps1") `
    -Arguments "-Profile $Profile" `
    -WorkingDirectory $InstallRoot `
    -Description "Inject a repeatable SOC demo scenario and open the dashboard."

New-AppShortcut `
    -ShortcutPath (Join-Path $ProgramsDir "Stop Cyber-EW.lnk") `
    -TargetScript (Join-Path $InstallRoot "scripts\stop_service.ps1") `
    -WorkingDirectory $InstallRoot `
    -Description "Stop Cyber-EW Fusion Cell."

if ($DesktopShortcut) {
    New-AppShortcut `
        -ShortcutPath (Join-Path ([Environment]::GetFolderPath("Desktop")) "Cyber-EW Fusion Cell.lnk") `
        -TargetScript (Join-Path $InstallRoot "scripts\open_dashboard.ps1") `
        -Arguments "-Profile $Profile" `
        -WorkingDirectory $InstallRoot `
        -Description "Start Cyber-EW Fusion Cell and open the dashboard."
}

if ($AutoStart) {
    & (Join-Path $InstallRoot "scripts\install_windows_task.ps1") -Profile $Profile
}

$Manifest = @{
    app = "Cyber-EW Fusion Cell"
    installed_at = (Get-Date).ToUniversalTime().ToString("o")
    install_dir = $InstallRoot
    profile = $Profile
    start_menu = $ProgramsDir
    desktop_shortcut = [bool]$DesktopShortcut
    autostart = [bool]$AutoStart
}
$ManifestPath = Join-Path $InstallRoot "data\outputs\app_install.json"
New-Item -ItemType Directory -Force -Path (Split-Path $ManifestPath) | Out-Null
$Manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $ManifestPath -Encoding UTF8

Write-Host ""
Write-Host "Installation complete."
Write-Host "Open from Start Menu: Cyber-EW Fusion Cell"
Write-Host "Dashboard URL: http://127.0.0.1:8501"
Write-Host "Uninstall command: powershell -ExecutionPolicy Bypass -File `"$InstallRoot\scripts\uninstall_app.ps1`""
