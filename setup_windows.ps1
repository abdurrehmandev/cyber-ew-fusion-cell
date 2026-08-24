<#
.SYNOPSIS
  Clean setup for Cyber-EW Fusion Cell on Windows.
  Relocates the project off OneDrive into a clean local folder, initializes git,
  creates a fresh Python 3.12 virtual environment, installs ALL dependencies,
  and runs verification. Your original OneDrive folder is only read, never changed.

.HOW TO RUN
  Open PowerShell, then:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    cd "$env:USERPROFILE\OneDrive\Documents\cyber-ew-fusion-cell"
    .\setup_windows.ps1

.PARAMETERS
  -Source : project to copy FROM (default: the folder this script lives in)
  -Dest   : clean local destination (default: C:\dev\cyber-ew-fusion-cell)
  -PyVer  : Python version via the 'py' launcher (default: 3.12)
#>

param(
  [string]$Source = $PSScriptRoot,
  [string]$Dest   = "C:\dev\cyber-ew-fusion-cell",
  [string]$PyVer  = "3.12"
)

$ErrorActionPreference = "Stop"

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){   Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m){ Write-Host "[X] $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Info "Cyber-EW Fusion Cell - Windows clean setup"
Info "Source : $Source"
Info "Dest   : $Dest"
Info "Python : $PyVer"
Write-Host ""

# ---------- 0. Prerequisite checks ----------
Info "Checking prerequisites (Python $PyVer and Git)..."
try { $pv = (& py -$PyVer --version 2>&1 | Out-String).Trim() } catch { $pv = "" }
if ($pv -notmatch ("Python " + [regex]::Escape($PyVer))) {
  Fail "Python $PyVer not found via the 'py' launcher. Install it from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH'), open a NEW PowerShell window, then re-run this script."
}
Ok "Found $pv"

try { $gv = (& git --version 2>&1 | Out-String).Trim() } catch { $gv = "" }
if (-not $gv) {
  Fail "Git not found. Install from https://git-scm.com/download/win, open a NEW PowerShell window, then re-run."
}
Ok "Found $gv"

# Source sanity + self-copy guard
if (-not (Test-Path (Join-Path $Source "main.py")) -or -not (Test-Path (Join-Path $Source "requirements.txt"))) {
  Fail "Source does not look like the project root (missing main.py / requirements.txt). cd into the project folder, then run .\setup_windows.ps1"
}
$srcFull = (Resolve-Path $Source).Path.TrimEnd('\')
$dstFull = $Dest.TrimEnd('\')
if ($srcFull -ieq $dstFull) { Fail "Source and destination are the same folder ($dstFull)." }

# ---------- 1. Relocate (robocopy, excluding cruft) ----------
if (Test-Path $Dest) {
  Warn "Destination already exists: $Dest"
  $ans = Read-Host "Type YES to copy into it anyway (existing files may be overwritten), or anything else to abort"
  if ($ans -ne "YES") { Fail "Aborted by user." }
} else {
  New-Item -ItemType Directory -Path $Dest -Force | Out-Null
}

Info "Copying real source (excluding venvs, build artifacts, caches, logs, and '- Copy' conflict files)..."
$excludeDirs  = @("venv","venv_old_broken","venv_legacy_broken_20260823",".venv","__pycache__",".pytest_cache","build","dist","temp","logs",".git")
$excludeFiles = @("*- Copy*","* - Copy*")
& robocopy $Source $Dest /E /NFL /NDL /NP /R:1 /W:1 /XD $excludeDirs /XF $excludeFiles | Out-Null
$rc = $LASTEXITCODE
if ($rc -ge 8) { Fail "robocopy failed with exit code $rc (>=8 indicates an error)." }
Ok "Copy complete (robocopy code $rc = success)"

# ---------- 2. .gitignore + git init ----------
Set-Location $Dest

Info "Writing .gitignore..."
$gitignore = @'
# Byte-compiled / caches
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
.pytest_cache/
.mypy_cache/
.coverage
htmlcov/

# Build artifacts
build/
dist/

# Virtual environments
.venv/
venv/
venv_*/
env/
ENV/

# Runtime output
logs/
*.log
temp/
tmp/
reports/*.json

# Secrets / local config (keep the example)
.env
*.env
!.env.example

# OS / editor
.DS_Store
Thumbs.db
*.swp
.idea/
.vscode/

# OneDrive conflict artifacts
* - Copy.*
*- Copy*
'@
Set-Content -Path (Join-Path $Dest ".gitignore") -Value $gitignore -Encoding UTF8
Ok ".gitignore written"

if (-not (Test-Path (Join-Path $Dest ".git"))) {
  Info "Initializing git repository..."
  & git init | Out-Null
  & git add -A
  & git -c user.email="setup@local" -c user.name="Setup Script" commit -m "Initial clean import of Cyber-EW Fusion Cell" | Out-Null
  Ok "git repository initialized with first commit"
} else {
  Warn "git repository already exists here - skipping git init"
}

# ---------- 3. venv + dependencies ----------
Info "Creating fresh virtual environment (.venv) with Python $PyVer..."
& py -$PyVer -m venv .venv
$py = Join-Path $Dest ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Fail "venv creation failed (no python.exe under .venv\Scripts)." }
Ok "venv created"

Info "Upgrading pip..."
& $py -m pip install --upgrade pip | Out-Null

Info "Installing all dependencies from requirements.txt (this can take several minutes)..."
& $py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Fail "pip install failed - see the error above, then check Part 7 (Troubleshooting) in SETUP.md." }
Ok "All pip dependencies installed"

# pywin32 post-install (best effort)
$pw = Join-Path $Dest ".venv\Scripts\pywin32_postinstall.py"
if (Test-Path $pw) {
  Info "Running pywin32 post-install..."
  try { & $py $pw -install | Out-Null; Ok "pywin32 post-install done" } catch { Warn "pywin32 post-install reported an issue (usually harmless)." }
}

# ---------- 4. Verification ----------
Write-Host ""
Info "VERIFY 1/2 -> python main.py --test"
& $py main.py --test
if ($LASTEXITCODE -ne 0) { Warn "main.py --test returned a nonzero exit code - review the output above." } else { Ok "main.py --test passed (exit 0)" }

Write-Host ""
Info "VERIFY 2/2 -> python -m pytest -q"
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { Warn "Some tests failed - review the output above (see SETUP.md Part 7)." } else { Ok "Test suite passed" }

# ---------- Done ----------
Write-Host ""
Ok "Windows setup complete."
Info "Project location : $Dest"
Info "Activate next time: cd `"$Dest`" ; .\.venv\Scripts\Activate.ps1"
Warn "For LIVE packet capture only: also install Npcap (https://npcap.com) and Wireshark (https://www.wireshark.org). See SETUP.md Part 3.3."
Write-Host ""
