param(
  [ValidateSet('install','uninstall','start','stop','status')] [string]$Action='install',
  [string]$ServiceName='CyberEW',
  [string]$RepoPath=(Get-Location).Path
)

# Ensure Node is available
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Error 'Node not found in PATH. Install Node.js and retry.'; exit 1 }

# Ensure build artifact exists (dist/server.js)
$dist = Join-Path $RepoPath 'dist\server.js'
if (-not (Test-Path $dist)) {
  Write-Host 'Building project (tsc)...' -ForegroundColor Yellow
  npm run build
  if (-not (Test-Path $dist)) { Write-Error 'Build missing: run npm run build manually'; exit 1 }
}

# Prepare NSSM binary path
$nssmExe = Join-Path $env:TEMP 'nssm.exe'
if (-not (Test-Path $nssmExe)) {
  Write-Host 'Downloading nssm...' -ForegroundColor Yellow
  $zip = Join-Path $env:TEMP 'nssm.zip'
  Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile $zip -UseBasicParsing
  Expand-Archive $zip -DestinationPath $env:TEMP -Force
  $cand = Get-ChildItem -Path $env:TEMP -Filter 'nssm.exe' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like '*win64*' } | Select-Object -First 1
  if (-not $cand) { $cand = Get-ChildItem -Path $env:TEMP -Filter 'nssm.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }
  if ($cand) { Copy-Item $cand.FullName $nssmExe -Force } else { Write-Error 'nssm binary not found'; exit 1 }
}

switch ($Action) {
  'install' {
    New-Item -ItemType Directory -Path (Join-Path $RepoPath 'logs') -Force | Out-Null
    & $nssmExe install $ServiceName $node $dist
    & $nssmExe set $ServiceName AppDirectory $RepoPath
    # Example: set NODE_ENV and optionally API_KEYS; modify to suit
    & $nssmExe set $ServiceName AppEnvironmentExtra "NODE_ENV=production"
    & $nssmExe set $ServiceName AppStdout (Join-Path $RepoPath 'logs\service-out.log')
    & $nssmExe set $ServiceName AppStderr (Join-Path $RepoPath 'logs\service-err.log')
    & $nssmExe set $ServiceName Start SERVICE_AUTO_START
    & $nssmExe start $ServiceName
    Write-Host "Service $ServiceName installed and started." -ForegroundColor Green
  }
  'uninstall' {
    & $nssmExe stop $ServiceName 2>$null
    & $nssmExe remove $ServiceName confirm
    Write-Host "Service $ServiceName removed." -ForegroundColor Green
  }
  'start' { & $nssmExe start $ServiceName }
  'stop'  { & $nssmExe stop $ServiceName }
  'status' { sc.exe query $ServiceName }
  default { Write-Error "Unknown action: $Action" }
}
