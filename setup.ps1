# Cyber-EW Fusion Cell: Windows 11 Quick Setup Script
# Run this script to automate the installation process

param(
    [ValidateSet("install", "start", "test", "export", "demo", "help")]
    [string]$Command = "help"
)

function Show-Help {
    @"
╔═══════════════════════════════════════════════════════════════════╗
║     Cyber-EW Fusion Cell: Windows 11 Quick Setup                 ║
╚═══════════════════════════════════════════════════════════════════╝

Usage: .\setup.ps1 -Command <command>

Commands:
  install    Install dependencies (run once)
  start      Start the pipeline server
  test       Run all tests
  demo       Generate attack scenario demo data
  export     Example: Export alerts in CEF/STIX/CSV format
  help       Show this help message

Examples:
  .\setup.ps1 -Command install
  .\setup.ps1 -Command start
  .\setup.ps1 -Command demo
  .\setup.ps1 -Command export

"@
}

function Check-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Cyan
    
    # Check Node.js
    $nodeVersion = node --version 2>$null
    if ($null -eq $nodeVersion) {
        Write-Host "❌ Node.js not installed!" -ForegroundColor Red
        Write-Host "   Download from: https://nodejs.org/" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "✓ Node.js $nodeVersion" -ForegroundColor Green
    
    # Check npm
    $npmVersion = npm --version 2>$null
    if ($null -eq $npmVersion) {
        Write-Host "❌ npm not installed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ npm $npmVersion" -ForegroundColor Green
    
    # Check data directory
    if (!(Test-Path "data")) {
        Write-Host "✓ Creating data directory..." -ForegroundColor Green
        New-Item -ItemType Directory -Path "data" -Force | Out-Null
    }
}

function Install-Dependencies {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Installing Dependencies                   ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Check-Prerequisites
    
    Write-Host "`nRunning: npm install" -ForegroundColor Yellow
    npm install
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ Dependencies installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "`n❌ Installation failed!" -ForegroundColor Red
        exit 1
    }
}

function Start-Pipeline {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Starting Cyber-EW Fusion Cell Pipeline    ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Check-Prerequisites
    
    Write-Host "`n🚀 Starting server on http://localhost:3000" -ForegroundColor Green
    Write-Host "📁 Watching: $(pwd)\data\inputs\live" -ForegroundColor Green
    Write-Host "💾 Saving alerts to: $(pwd)\data\outputs\alerts.jsonl" -ForegroundColor Green
    Write-Host "`n⏹️  Press Ctrl+C to stop the server`n" -ForegroundColor Yellow
    
    npm run dev
}

function Run-Tests {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Running Test Suite                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Check-Prerequisites
    
    Write-Host "`nRunning: npm test" -ForegroundColor Yellow
    npm test
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ All tests passed!" -ForegroundColor Green
    } else {
        Write-Host "`n❌ Some tests failed!" -ForegroundColor Red
    }
}

function Generate-Demo {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Generating Attack Scenario Demo Data       ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Check-Prerequisites
    
    Write-Host "`nScenarios to be generated:" -ForegroundColor Green
    Write-Host "  • Credential Stuffing (50 SSH login attempts)" -ForegroundColor Cyan
    Write-Host "  • Lateral Movement (SMB + RDP connections)" -ForegroundColor Cyan
    Write-Host "  • Data Exfiltration (bulk data transfers)" -ForegroundColor Cyan
    Write-Host "  • Ransomware Propagation (multi-target)" -ForegroundColor Cyan
    
    Write-Host "`nRunning: npx ts-node scripts/generate_attack_scenario.ts`n" -ForegroundColor Yellow
    npx ts-node scripts/generate_attack_scenario.ts
    
    Write-Host "`n✓ Demo data generated!" -ForegroundColor Green
    Write-Host "  Files created in: data\inputs\live\" -ForegroundColor Cyan
    Write-Host "  (Ingest worker will process them automatically)" -ForegroundColor Cyan
}

function Export-Alerts {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Exporting Alerts in Multiple Formats      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $baseUrl = "http://localhost:3000/api/export"
    
    Write-Host "`nMake sure the server is running (npm run dev in another window)" -ForegroundColor Yellow
    Write-Host "`nAvailable export endpoints:" -ForegroundColor Cyan
    
    Write-Host "`n1️⃣  CEF Format (for SIEM):" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/alerts?format=cef&limit=5' -OutFile 'alerts.cef'" -ForegroundColor Yellow
    
    Write-Host "`n2️⃣  CSV Format (for Excel):" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/alerts?format=csv&limit=100' -OutFile 'alerts.csv'" -ForegroundColor Yellow
    
    Write-Host "`n3️⃣  STIX Format (for threat intel):" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/alerts?format=stix' -OutFile 'alerts.json'" -ForegroundColor Yellow
    
    Write-Host "`n4️⃣  JSON Lines (native format):" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/alerts?format=jsonl&limit=50' -OutFile 'alerts.jsonl'" -ForegroundColor Yellow
    
    Write-Host "`n5️⃣  Syslog Format (for syslog collectors):" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/stream/syslog?limit=100' -OutFile 'alerts.log'" -ForegroundColor Yellow
    
    Write-Host "`n6️⃣  Format Information:" -ForegroundColor Green
    Write-Host "   PowerShell:`n   " -NoNewline
    Write-Host "Invoke-RestMethod -Uri '$baseUrl/formats' | ConvertTo-Json | Write-Host" -ForegroundColor Yellow
    
    Write-Host "`n💡 Example: Export first 10 high-severity alerts as CEF:" -ForegroundColor Cyan
    Write-Host "   " -NoNewline
    Write-Host "Invoke-WebRequest -Uri '$baseUrl/alerts?format=cef&limit=10&threat_level=High' -OutFile 'high_alerts.cef'" -ForegroundColor Yellow
}

# Main execution
switch ($Command.ToLower()) {
    "install" { Install-Dependencies }
    "start" { Start-Pipeline }
    "test" { Run-Tests }
    "demo" { Generate-Demo }
    "export" { Export-Alerts }
    "help" { Show-Help }
    default { Show-Help }
}
