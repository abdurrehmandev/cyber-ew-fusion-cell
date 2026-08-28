# Cyber-EW Fusion Cell: Windows 11 Installation Guide

## Complete Step-by-Step Installation & Setup

This guide walks you through installing and running the Cyber-EW Fusion Cell cyber threat telemetry pipeline on **Windows 11**.

---

## Prerequisites

### System Requirements
- **OS**: Windows 11 (or Windows 10 with WSL 2)
- **RAM**: Minimum 4GB (8GB+ recommended)
- **Disk Space**: 2GB for installation + 1GB for sample data
- **CPU**: Dual-core or better

### Required Software (To Install)
1. **Node.js** (v18.0.0 or later)
2. **npm** (comes with Node.js)
3. **Git** (for cloning the repository)
4. **Visual Studio Code** (optional, but recommended)

---

## Step 1: Install Node.js

### On Windows 11:

1. Open a **PowerShell or Command Prompt** (or Windows Terminal)

2. Download Node.js from the official website:
   ```powershell
   # Open your web browser and navigate to:
   # https://nodejs.org/
   ```

3. **Download LTS version** (Long-Term Support):
   - Click "Download 20.x LTS" (or latest LTS available)
   - This will download an `.msi` installer

4. **Run the installer**:
   - Double-click the downloaded `.msi` file
   - Click "Next" through the installation wizard
   - Keep default settings (include npm)
   - Click "Install"
   - Click "Finish" when done

5. **Verify installation**:
   ```powershell
   node --version
   npm --version
   ```
   Output should show versions like `v20.x.x` and `10.x.x`

---

## Step 2: Install Git (Optional but Recommended)

### On Windows 11:

1. Visit https://git-scm.com/download/win

2. Download the Windows installer (`.exe`)

3. Run the installer:
   - Click "Next" through all screens
   - Keep default settings
   - Click "Finish"

4. **Verify installation**:
   ```powershell
   git --version
   ```

---

## Step 3: Clone or Download the Repository

### Option A: Using Git (Recommended)

```powershell
# Navigate to where you want to store the project
cd C:\Users\YourUsername\Documents

# Clone the repository
git clone https://github.com/abdurrehmandev/cyber-ew-fusion-cell.git

# Navigate into the project
cd cyber-ew-fusion-cell
```

### Option B: Manual Download

1. Go to: https://github.com/abdurrehmandev/cyber-ew-fusion-cell
2. Click **"Code"** → **"Download ZIP"**
3. Extract the ZIP file to `C:\Users\YourUsername\Documents\`
4. Rename folder to `cyber-ew-fusion-cell` (optional)
5. Open PowerShell/CMD and navigate to the folder:
   ```powershell
   cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell
   ```

---

## Step 4: Install Project Dependencies

Once inside the project directory:

```powershell
# Install npm dependencies
npm install
```

This will download and install all required packages. **This may take 2-5 minutes.**

### Expected Output:
```
added 500+ packages in 2m
```

---

## Step 5: Start the Pipeline

### Start in Development Mode:

```powershell
# From the project root directory
npm run dev
```

### Expected Console Output:
```
[Cyber-EW Fusion Cell] Server running on http://localhost:3000
[ingestWorker] Starting file watcher for C:\...\data\inputs\live
```

### Access the Dashboard:

1. Open your web browser (Chrome, Firefox, Edge)
2. Navigate to: **http://localhost:3000**
3. You should see the Cyber-EW Fusion Cell dashboard

**To stop the server**: Press `Ctrl+C` in PowerShell

---

## Step 6: Generate Demo Attack Scenarios

Open a **new PowerShell window** (keep the server running):

```powershell
# Navigate to project directory
cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell

# Generate attack scenarios
npx ts-node scripts/generate_attack_scenario.ts
```

### Expected Output:
```
Generating attack scenario telemetry...

✓ Generated scenario: credential_stuffing (50 events) → data/inputs/live/scenario_credential_stuffing_1693180800000.jsonl
✓ Generated scenario: lateral_movement (4 events) → data/inputs/live/scenario_lateral_movement_1693180800001.jsonl
✓ Generated scenario: data_exfiltration (10 events) → data/inputs/live/scenario_data_exfiltration_1693180800002.jsonl
✓ Generated scenario: ransomware_propagation (4 events) → data/inputs/live/scenario_ransomware_propagation_1693180800003.jsonl

✓ All scenarios generated. Ingest watcher will process them automatically.
```

---

## Step 7: Verify Data Processing

### Monitor Alert Output:

```powershell
# In a new PowerShell window:
cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell

# View ingested alerts (live tail)
Get-Content -Path data\outputs\alerts.jsonl -Tail 10 -Wait
```

Or simply check the file:

```powershell
# List files processed
dir data\inputs\live\processed

# Check alert count
(Get-Content data\outputs\alerts.jsonl | Measure-Object -Line).Lines
```

---

## Step 8: Test the Export Engine

The output engine supports multiple formats: **CEF, STIX, CSV, JSON, Syslog**.

### Using PowerShell to test export endpoints:

```powershell
# Test: Get alerts as CEF format
$response = Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=cef&limit=5" -OutFile "alerts.cef"
Write-Host "CEF export saved to alerts.cef"

# Test: Get alerts as CSV format
$response = Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=csv&limit=100" -OutFile "alerts.csv"
Write-Host "CSV export saved to alerts.csv"

# Test: Get alerts as STIX format
$response = Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=stix" -OutFile "alerts_stix.json"
Write-Host "STIX export saved to alerts_stix.json"

# Test: Get format information
Invoke-RestMethod -Uri "http://localhost:3000/api/export/formats" | ConvertTo-Json | Write-Host
```

---

## Step 9: Run Tests

To verify the pipeline is working correctly:

```powershell
# Run all tests
npm test

# Run tests in watch mode (auto-rerun on changes)
npm run test:watch
```

### Expected Output:
```
PASS  tests/api.test.ts
PASS  tests/engines.test.ts
PASS  tests/output.test.ts

Test Suites: 3 passed, 3 total
Tests:       25 passed, 25 total
```

---

## Step 10: Explore the API

### Using PowerShell to interact with the API:

```powershell
# Get health status
Invoke-RestMethod -Uri "http://localhost:3000/api/health" | ConvertTo-Json

# Get ingestion statistics
Invoke-RestMethod -Uri "http://localhost:3000/api/ingest/stats" | ConvertTo-Json

# Query first 5 alerts
Invoke-RestMethod -Uri "http://localhost:3000/api/ingest/alerts?limit=5" | ConvertTo-Json

# Get alerts as CSV format
Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=csv&limit=50" -OutFile "export_alerts.csv"
Invoke-Item "export_alerts.csv"  # Opens in default app (Excel, etc.)
```

---

## Optional: Run with Docker (Recommended for reproducible deployment)

If you prefer containerized deployment, Docker is supported. This avoids local Node.js dependency issues and provides a reproducible runtime.

1. Install Docker Desktop for Windows: https://docs.docker.com/desktop/windows/install/
2. From the project root, build and run the container:
   ```powershell
   docker-compose build
docker-compose up -d
   ```
3. The service will be available on http://localhost:3000 by default.
4. Telemetry files and state persist on the host under the `data/` directory (mapped into the container).

---

## Step 11: Ingest Custom Telemetry

You can manually drop telemetry files into `data/inputs/live/` and they will be automatically processed.

### Supported file formats:
- `.jsonl` or `.eve` — Suricata IDS/IPS alerts
- `.tsv` — Zeek network telemetry
- `.log` — Syslog messages
- `.json` — Windows Event Log (JSON format)

### Example: Add Suricata alert manually

```powershell
# Create a sample Suricata event
$event = @{
    timestamp = Get-Date -AsUTC | Get-Date -Format 'o'
    src_ip = "192.168.1.55"
    dest_ip = "198.51.100.200"
    dest_port = 443
    alert = @{ signature = "Manual test alert" }
} | ConvertTo-Json

# Save to ingest directory
$event | Out-File -FilePath "data\inputs\live\manual_test.jsonl"

Write-Host "Alert added. Check data\outputs\alerts.jsonl in a few seconds..."
```

---

## Troubleshooting on Windows 11

### Issue: "npm not found"
```powershell
# Solution: Add Node.js to PATH
# Restart PowerShell after installing Node.js, or:
$env:Path = "C:\Program Files\nodejs;" + $env:Path
npm --version
```

### Issue: "Port 3000 already in use"
```powershell
# Find process using port 3000
netstat -ano | findstr :3000

# Kill the process (replace PID)
Stop-Process -Id <PID> -Force
```

### Issue: "File access denied" when processing files
```powershell
# Solution: Close files in other programs (Excel, text editors)
# Windows locks files opened in other applications
```

### Issue: "Cannot find module 'express'"
```powershell
# Solution: Reinstall dependencies
rm -Recurse node_modules
rm package-lock.json
npm install
```

### Issue: Alerts not appearing in outputs/
```powershell
# Check if file watcher is running (should see in server logs):
# "[ingestWorker] Starting file watcher for ..."

# Check if input directory exists:
dir data\inputs\live

# Check console for errors in your PowerShell window running npm run dev
```

---

## Optional: Create a Batch Script for Easy Startup

Create a file called `start_pipeline.bat` in your project folder:

```batch
@echo off
cd /d %~dp0
title Cyber-EW Fusion Cell
npm run dev
pause
```

Double-click this file to start the pipeline in the future.

---

## Project Structure Reference

```
cyber-ew-fusion-cell/
├── server.ts                    # Main Express server
├── server/
│   ├── ingestWorker.ts          # File watcher
│   ├── normalization.ts         # Multi-format telemetry normalization
│   ├── correlation.ts           # Correlation engine
│   ├── behavior.ts              # Behavior profiling
│   ├── scoring.ts               # Threat scoring
│   └── output.ts                # ✅ NEW: Output format engine (CEF, STIX, CSV, Syslog)
├── data/
│   ├── inputs/live/             # Drop telemetry files here
│   │   └── processed/           # Automatically archived
│   └── outputs/
│       └── alerts.jsonl         # Processed alerts
├── tests/
│   ├── api.test.ts              # API tests
│   ├── engines.test.ts          # Engine unit tests
│   └── output.test.ts           # ✅ NEW: Output engine tests
├── scripts/
│   └── generate_attack_scenario.ts  # Demo scenario generator
├── docs/
│   ├── ARCHITECTURE.md          # System design
│   └── README.md                # User guide
└── package.json                 # Dependencies
```

---

## API Endpoints Summary

### Health & Stats
- `GET /api/health` — System health status
- `GET /api/ingest/stats` — Telemetry statistics

### Queries
- `GET /api/ingest/alerts` — Query alerts
- `GET /api/ingest/timeline` — Event timeline

### Ingestion
- `POST /api/ingest/raw` — Direct HTTP ingestion

### **✅ Export (NEW OUTPUT ENGINE)**
- `GET /api/export/alerts?format=cef|stix|csv|syslog|jsonl` — Export alerts in format
- `GET /api/export/alerts/:alert_id` — Export single alert
- `GET /api/export/stream/cef` — Stream CEF for SIEM
- `GET /api/export/stream/syslog` — Stream Syslog
- `GET /api/export/formats` — Format documentation

---

## Next Steps

1. **Explore the Dashboard** — Check http://localhost:3000 for UI
2. **Review Documentation** — Read `docs/ARCHITECTURE.md`
3. **Ingest Real Data** — Drop your own telemetry files into `data/inputs/live/`
4. **Export to SIEM** — Use CEF/Syslog streaming endpoints to connect to Splunk, ELK, etc.
5. **Modify Scoring Rules** — Edit `server/scoring.ts` to customize threat calculations

---

## Support & Resources

- **GitHub**: https://github.com/abdurrehmandev/cyber-ew-fusion-cell
- **Issues**: Report problems on GitHub Issues
- **Docs**: See `docs/` folder for detailed documentation

---

**Installation Complete! Your Cyber-EW Fusion Cell is ready to process threat telemetry.** 🎉
