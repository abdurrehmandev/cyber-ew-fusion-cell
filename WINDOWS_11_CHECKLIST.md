# ✅ CYBER-EW FUSION CELL: WINDOWS 11 INSTALLATION CHECKLIST

Complete this checklist to install and verify the Cyber-EW Fusion Cell on Windows 11.

---

## PRE-INSTALLATION (5 minutes)

- [ ] **System Check**
  - [ ] Running Windows 11 (or Windows 10 with WSL 2)
  - [ ] At least 4GB RAM available
  - [ ] 2GB free disk space
  - [ ] Internet connection available

- [ ] **Software Requirements Check**
  - [ ] No previous installation conflicts
  - [ ] Can install Node.js and npm
  - [ ] PowerShell or Command Prompt available

---

## STEP 1: INSTALL NODE.JS (5 minutes)

- [ ] **Download Node.js LTS**
  - [ ] Visit https://nodejs.org/
  - [ ] Download "20.x LTS" version
  - [ ] Save `.msi` installer to Downloads

- [ ] **Install Node.js**
  - [ ] Double-click `.msi` file
  - [ ] Click "Next" through wizard
  - [ ] Select "Automatically install tools"
  - [ ] Click "Install"
  - [ ] Click "Finish"

- [ ] **Verify Installation**
  ```powershell
  node --version          # Should show v20.x.x
  npm --version           # Should show 10.x.x
  ```

---

## STEP 2: INSTALL GIT (Optional, 2 minutes)

- [ ] **Download Git**
  - [ ] Visit https://git-scm.com/download/win
  - [ ] Download latest Windows installer

- [ ] **Install Git**
  - [ ] Double-click `.exe` installer
  - [ ] Click "Next" through all screens
  - [ ] Keep default settings
  - [ ] Click "Finish"

- [ ] **Verify Installation**
  ```powershell
  git --version           # Should show git version
  ```

---

## STEP 3: CLONE/DOWNLOAD PROJECT (5 minutes)

### Option A: Using Git (Recommended)
- [ ] Open PowerShell
- [ ] Navigate to your Documents folder:
  ```powershell
  cd C:\Users\YourUsername\Documents
  ```
- [ ] Clone repository:
  ```powershell
  git clone https://github.com/abdurrehmandev/cyber-ew-fusion-cell.git
  ```
- [ ] Enter project:
  ```powershell
  cd cyber-ew-fusion-cell
  ```

### Option B: Manual Download
- [ ] Visit GitHub repository
- [ ] Click "Code" → "Download ZIP"
- [ ] Extract ZIP to Documents folder
- [ ] Rename to `cyber-ew-fusion-cell` (optional)
- [ ] Open PowerShell and navigate:
  ```powershell
  cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell
  ```

---

## STEP 4: INSTALL DEPENDENCIES (3-5 minutes)

- [ ] Ensure you're in project directory:
  ```powershell
  pwd  # Should end with \cyber-ew-fusion-cell
  ```

- [ ] Install npm packages:
  ```powershell
  npm install
  ```
  - [ ] Wait for completion (may take 3-5 minutes)
  - [ ] Look for "added 500+ packages" message

- [ ] Verify installation:
  ```powershell
  npm list --depth=0  # Shows top-level packages
  ```

---

## STEP 5: START THE SERVER (2 minutes)

- [ ] Keep current PowerShell window open
- [ ] Start development server:
  ```powershell
  npm run dev
  ```

- [ ] Verify server started:
  - [ ] Look for: `[Cyber-EW Fusion Cell] Server running on http://localhost:3000`
  - [ ] Look for: `[ingestWorker] Starting file watcher`

- [ ] Open browser and visit: **http://localhost:3000**
  - [ ] You should see the Cyber-EW Fusion Cell dashboard
  - [ ] Leave this server running

---

## STEP 6: GENERATE DEMO DATA (2 minutes)

- [ ] **Open NEW PowerShell window** (leave previous one running)
- [ ] Navigate to project:
  ```powershell
  cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell
  ```

- [ ] Generate attack scenarios:
  ```powershell
  npx ts-node scripts/generate_attack_scenario.ts
  ```

- [ ] Verify output:
  - [ ] Look for "✓ Generated scenario: credential_stuffing"
  - [ ] Look for "✓ Generated scenario: lateral_movement"
  - [ ] Look for "✓ Generated scenario: data_exfiltration"
  - [ ] Look for "✓ Generated scenario: ransomware_propagation"

- [ ] Check first server window:
  - [ ] Should see `[ingestWorker] Appended X alerts` messages

---

## STEP 7: VERIFY ALERT INGESTION (2 minutes)

- [ ] **Open THIRD PowerShell window**
- [ ] Navigate to project:
  ```powershell
  cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell
  ```

- [ ] Check alert file:
  ```powershell
  dir data\outputs\alerts.jsonl
  ```
  - [ ] File should exist
  - [ ] File should have size > 0 KB

- [ ] View last 5 alerts:
  ```powershell
  Get-Content -Path data\outputs\alerts.jsonl -Tail 5
  ```
  - [ ] Should see JSON-formatted alerts
  - [ ] Should include fields: alert_id, timestamp, threat_level, threat_score

---

## STEP 8: TEST REST API (3 minutes)

In the THIRD PowerShell window, test API endpoints:

- [ ] **Health Check**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/health" | ConvertTo-Json
  ```
  - [ ] Should return `"status": "ok"`

- [ ] **Statistics**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/ingest/stats" | ConvertTo-Json
  ```
  - [ ] Should show alert counts by threat level

- [ ] **Query Alerts**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/ingest/alerts?limit=3" | ConvertTo-Json
  ```
  - [ ] Should return array of alerts

---

## STEP 9: TEST OUTPUT EXPORT ENGINE (5 minutes)

The new Output Engine exports alerts in multiple formats.

- [ ] **Export as CEF** (for Splunk, ELK):
  ```powershell
  Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=cef&limit=5" -OutFile "alerts.cef"
  Get-Content alerts.cef | Select-Object -First 1
  ```
  - [ ] Should start with `CEF:0|CyberEW|FusionCell`

- [ ] **Export as CSV** (for Excel):
  ```powershell
  Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=csv&limit=10" -OutFile "alerts.csv"
  Invoke-Item alerts.csv
  ```
  - [ ] Should open in Excel (or default spreadsheet app)
  - [ ] Should have headers and data rows

- [ ] **Export as STIX** (for threat intel):
  ```powershell
  Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=stix&limit=5" -OutFile "alerts.json"
  Get-Content alerts.json | Select-Object -First 20
  ```
  - [ ] Should contain `"type": "bundle"`
  - [ ] Should contain observable objects

- [ ] **Export format info**:
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/export/formats" | ConvertTo-Json
  ```
  - [ ] Should show all supported formats
  - [ ] Should show example exports

---

## STEP 10: RUN TEST SUITE (2 minutes)

- [ ] **Open FOURTH PowerShell window**
- [ ] Navigate to project:
  ```powershell
  cd C:\Users\YourUsername\Documents\cyber-ew-fusion-cell
  ```

- [ ] Run all tests:
  ```powershell
  npm test
  ```

- [ ] Verify results:
  - [ ] Look for "Test Suites: X passed, X total"
  - [ ] Look for "Tests: X passed, X total"
  - [ ] All tests should PASS ✓

---

## STEP 11: VERIFY DATA FILES (1 minute)

- [ ] Check input directory:
  ```powershell
  dir data\inputs\live
  ```
  - [ ] Should have `processed` subfolder
  - [ ] May have scenario files (being processed)

- [ ] Check processed files:
  ```powershell
  dir data\inputs\live\processed | Select-Object -First 5
  ```
  - [ ] Should see timestamped files

- [ ] Check output alerts:
  ```powershell
  (Get-Content data\outputs\alerts.jsonl | Measure-Object -Line).Lines
  ```
  - [ ] Should show total number of alerts (e.g., "68")

---

## STEP 12: REVIEW DOCUMENTATION (5 minutes)

- [ ] **Read installation guide:**
  - [ ] Open `WINDOWS_11_INSTALL.md`
  - [ ] Review steps for future reference

- [ ] **Review architecture:**
  - [ ] Open `docs\ARCHITECTURE.md`
  - [ ] Understand pipeline flow (Ingest → Normalize → Correlate → Behavior → Score → Export)

- [ ] **Check examples:**
  - [ ] Open `README.md`
  - [ ] Review Quick Start section

---

## POST-INSTALLATION VERIFICATION

- [ ] **All 3 server windows running** (no errors)
  - [ ] Window 1: `npm run dev` (server + file watcher)
  - [ ] Window 2/3/4: Test & utility windows

- [ ] **All tests passing**
  ```powershell
  npm test
  ```
  - [ ] Should see "Test Suites: 3 passed"
  - [ ] Should see "Tests: 40+ passed"

- [ ] **API responding**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/health"
  ```
  - [ ] Should return JSON with status: "ok"

- [ ] **Alerts being ingested**
  ```powershell
  (Get-Content data\outputs\alerts.jsonl | Measure-Object -Line).Lines
  ```
  - [ ] Should show > 50 alerts

- [ ] **Export working**
  ```powershell
  Invoke-WebRequest -Uri "http://localhost:3000/api/export/alerts?format=csv" -OutFile "test.csv"
  Test-Path test.csv
  ```
  - [ ] Should return `True`

---

## TROUBLESHOOTING

| Issue | Solution |
| --- | --- |
| "npm not found" | Restart PowerShell after Node.js install, or add to PATH |
| Port 3000 in use | `netstat -ano \| findstr :3000` → `Stop-Process -Id <PID> -Force` |
| "Cannot find module" | Delete `node_modules`, delete `package-lock.json`, run `npm install` |
| Alerts not appearing | Check server window for errors, verify input files in `data/inputs/live/` |
| Tests failing | Delete `node_modules`, run `npm install`, run `npm test` again |
| Export file empty | Wait a few seconds after generating demo data before exporting |

---

## SUCCESS CHECKLIST ✅

When you can complete ALL of these, your installation is successful:

- [ ] Node.js and npm installed and verified
- [ ] Project cloned/downloaded
- [ ] Dependencies installed (npm install successful)
- [ ] Server running on http://localhost:3000
- [ ] Dashboard visible in browser
- [ ] Demo data generated successfully
- [ ] Alerts appearing in `data/outputs/alerts.jsonl`
- [ ] API endpoints responding (health, stats, alerts)
- [ ] Output engine exports working (CEF, CSV, STIX)
- [ ] All tests passing (npm test)
- [ ] No errors in any PowerShell window

---

## NEXT STEPS

Once installation is complete:

1. **Explore the Dashboard** — Visit http://localhost:3000
2. **Ingest Real Data** — Drop telemetry into `data/inputs/live/`
3. **Export to SIEM** — Use CEF/Syslog streams for Splunk/ELK
4. **Read Documentation** — Review `docs/ARCHITECTURE.md`
5. **Customize Scoring** — Edit `server/scoring.ts` for your needs
6. **Deploy to Production** — Use `npm run build && npm run start`

---

## 🎉 Congratulations!

Your Cyber-EW Fusion Cell is now installed and operational on Windows 11!

- **Status**: ✅ Fully Functional
- **Version**: 1.2.0
- **Deployment Ready**: Yes
- **SIEM Integration**: Enabled (CEF, Syslog streaming)
- **Test Coverage**: 40+ tests passing

**Start processing threat telemetry now!**

---

**Last Updated**: 2026-08-27  
**Document**: Windows 11 Installation Checklist  
**Status**: Complete & Verified
