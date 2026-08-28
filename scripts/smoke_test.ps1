# Simple smoke test for Cyber-EW Node API
# Usage: Start the app (npm run dev) then run this script in PowerShell

$url = 'http://localhost:3000/api/health'
$outFile = "$env:TEMP\cyber_ew_smoke_health.json"

Write-Output "Checking $url ..."
try {
    $resp = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5
    $resp | ConvertTo-Json -Depth 5 | Out-File -FilePath $outFile -Encoding utf8
    Write-Output "OK: saved response to $outFile"
    Write-Output ($resp | ConvertTo-Json -Depth 3)
    exit 0
} catch {
    Write-Error "Failed to reach $url: $_"
    exit 2
}
