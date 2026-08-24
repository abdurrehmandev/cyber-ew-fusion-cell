# Cyber-EW Fusion Cell

Cyber-EW Fusion Cell is a defensive cyber intelligence fusion engine. It ingests network and host telemetry, normalizes events, correlates activity across time and entities, detects behavior patterns, scores threat severity, and emits SOC-friendly alerts.

The project is designed for on-prem and air-gapped SOC environments where repeatable local processing matters more than cloud dependency.

## Current Capabilities

- Ingests PCAP-like files, syslog-style logs, local files, mock telemetry sources, and production sensor exports.
- Auto-detects Suricata `eve.json`/JSONL, Zeek TSV logs, and Windows/Sysmon-style JSON.
- Normalizes telemetry into the `NormalizedEvent` model with UTC timestamps.
- Correlates events by time window and shared entities.
- Builds behavioral profiles and detects anomalies, credential stuffing, lateral movement, ransomware-like file activity, C2 beaconing, data staging, privilege escalation, and exfiltration.
- Scores events with behavior, correlation, signature, ML anomaly, and threat-intelligence signals.
- Outputs alerts as console, JSON, CSV, CEF, and STIX-like structures.
- Saves pipeline statistics and behavioral profiles under `data/`.
- Provides an analyst dashboard with alert triage, case workflow, IOC watchlist, hunt workspace, ATT&CK timeline, operational health, and export bundles.
- Builds MITRE ATT&CK-style investigation reports with tactics, techniques, evidence, and timeline exports.
- Provides a local REST API for health, metrics, alerts, cases, IOCs, audit records, and SOC bundle export.
- Supports optional live Windows Event Log/Sysmon collection and Scapy/Npcap packet metadata capture for enterprise pilots.

## Quick Start

Use the Python interpreter available on your system or recreate the broken virtual environment first.

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
```

### OneDrive Files On-Demand

If the project is stored in OneDrive and Python imports stall, use the local-runtime
launcher. It mirrors only the runnable source and data into `%LOCALAPPDATA%` before
starting, leaving this folder as the editable source of truth:

```powershell
.\scripts\run_local_runtime.ps1 -Command test
.\scripts\run_local_runtime.ps1 -Command start -Profile production
```

Use the operator CLI for normal work:

```powershell
venv\Scripts\python.exe manage.py doctor
venv\Scripts\python.exe manage.py start
venv\Scripts\python.exe manage.py status
venv\Scripts\python.exe manage.py demo
venv\Scripts\python.exe manage.py test
```

Operator commands:

- `manage.py doctor`: validate dependencies, paths, ports, and service health.
- `manage.py start`: start pipeline, dashboard, and API.
- `manage.py stop`: stop managed service processes.
- `manage.py restart`: clean restart.
- `manage.py status`: print health and write `data/outputs/operator_health.json`.
- `manage.py demo`: start the service if needed and inject a fresh attack scenario into live ingestion.
- `manage.py test`: run compile, `test_all.py`, pytest smoke tests, and `main.py --test`.
- `manage.py logs`: show the latest log tail.
- `manage.py open`: open the dashboard.
- `manage.py profiles`: list deployment profiles.
- `manage.py report`: write deployment and security readiness reports.
- `manage.py cleanup`: apply retention policy and archive old local artifacts.

Deployment profiles:

- `dev`: local development profile.
- `demo`: presentation/demo profile.
- `offline`: air-gapped local profile with API key enforcement.
- `production`: hardened local SOC profile with API key enforcement and longer retention.

Example:

```powershell
venv\Scripts\python.exe manage.py start --profile production
venv\Scripts\python.exe manage.py report --profile production
```

Run the built-in smoke test:

```powershell
venv\Scripts\python.exe main.py --test --verbose
```

Start live monitoring:

```powershell
venv\Scripts\python.exe main.py --monitor
```

Run the full local live service:

```powershell
venv\Scripts\python.exe run_live.py
```

This starts:

- Detection pipeline
- Streamlit dashboard on `http://127.0.0.1:8501`
- REST API on `http://127.0.0.1:8080`

Drop telemetry files into `data/inputs/live/`; the pipeline will ingest new files and persist alerts to `data/outputs/alerts.jsonl`.

Production sensor files supported in the live drop folder:

- Suricata: `.json`, `.jsonl`, `.eve` records with `src_ip`, `dest_ip`, and `alert` fields.
- Zeek: `.log` or `.tsv` files with `#fields` headers, including `conn.log`, `dns.log`, and `http.log`.
- Windows/Sysmon: JSON exports with `EventID`, `EventData`, Winlogbeat `winlog.*`, or process/file/network fields.

Start the analyst dashboard:

```powershell
venv\Scripts\python.exe run_dashboard.py
```

Then open `http://127.0.0.1:8501`.

Start only the REST API:

```powershell
venv\Scripts\python.exe run_api.py
```

Useful local API endpoints:

- `GET /health`: service heartbeat and persisted alert count.
- `GET /readiness`: storage and engine readiness.
- `GET /metrics`: pipeline, case, IOC, and alert metrics.
- `GET /alerts?limit=100`: recent deduplicated alerts.
- `GET /attack/timeline?limit=250`: ATT&CK-style timeline and investigation summary.
- `GET /cases`: analyst cases.
- `POST /cases`: create or update a case.
- `GET /iocs`: local IOC watchlist.
- `POST /iocs`: add or update an IOC.
- `GET /audit`: recent analyst actions.
- `GET /export/bundle`: SOC evidence bundle.

Set `CYBER_EW_API_KEY` before starting the API to require `X-API-Key` on mutating endpoints.

Open the interactive console:

```powershell
venv\Scripts\python.exe main.py --mode console
```

Generate sample telemetry:

```powershell
venv\Scripts\python.exe scripts\generate_sample_data.py --count 100
```

Inject a live SOC demo scenario into the running dashboard:

```powershell
venv\Scripts\python.exe manage.py demo --count 120 --wait 15
```

This writes fresh JSON telemetry into `data/inputs/live/`, keeps a syslog copy under
`data/inputs/sample_generated/`, and waits for the live pipeline counters to move.

Simulate live pipeline alerts for dashboard testing:

```powershell
venv\Scripts\python.exe scripts\simulate_live_alerts.py --clear --count 6
```

Archive old local artifacts using the selected profile retention policy:

```powershell
venv\Scripts\python.exe manage.py cleanup --profile production
```

Preview cleanup without moving or rewriting files:

```powershell
venv\Scripts\python.exe manage.py cleanup --profile production --dry-run
```

## Windows Operator Scripts

Install Cyber-EW as a per-user Windows app with Start Menu shortcuts:

```powershell
.\scripts\install_app.ps1 -Profile production -DesktopShortcut
```

After installation, open it from the Start Menu:

- `Cyber-EW Fusion Cell`: starts the system and opens the dashboard.
- `Cyber-EW Status`: runs health and deployment checks.
- `Cyber-EW Demo Scenario`: injects demo telemetry and opens the dashboard.
- `Stop Cyber-EW`: stops the local service.

Install with auto-start at Windows logon:

```powershell
.\scripts\install_app.ps1 -Profile production -DesktopShortcut -AutoStart
```

Default install location:

```text
%LOCALAPPDATA%\CyberEWFusionCell
```

Uninstall the app:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\CyberEWFusionCell\scripts\uninstall_app.ps1"
```

These scripts use the project virtual environment and call `manage.py` for you:

```powershell
.\scripts\start_service.ps1 -Profile production
.\scripts\status_service.ps1 -Profile production
.\scripts\stop_service.ps1
```

Install an optional Windows Task Scheduler entry to start Cyber-EW at user logon:

```powershell
.\scripts\install_windows_task.ps1 -Profile production -RunNow
```

Remove the scheduled task:

```powershell
.\scripts\uninstall_windows_task.ps1
```

## Enterprise Packaging

Live collector and service mode:

```powershell
python main.py install-service
python main.py start-service
python main.py stop-service
python main.py remove-service
```

Build the standalone desktop executable with PyInstaller:

```powershell
.\scripts\build_exe.ps1 -SkipInstaller
```

Build a setup installer with Inno Setup 6 installed:

```powershell
.\scripts\build_exe.ps1
```

If Inno Setup is not installed yet:

```powershell
winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
```

The installer is written to `dist\installer\Cyber-EW-Fusion-Cell-Setup.exe`.
The installed app opens as a normal Windows desktop application. It does not add
itself to Windows startup and it does not open an external browser.

Optional Sysmon helper:

```powershell
.\scripts\install_sysmon.ps1 -SysmonExe C:\Tools\Sysmon64.exe -AcceptEula
```

See [Enterprise Deployment](docs/ENTERPRISE_DEPLOYMENT.md) for service mode,
registry configuration, packet capture, Sysmon, PyInstaller, and Inno Setup.

## Architecture

```mermaid
flowchart LR
    A["Ingest Engine"] --> B["Normalization Engine"]
    B --> C["Correlation Engine"]
    C --> D["Behavior Engine"]
    D --> E["Scoring Engine"]
    E --> F["Output Engine"]
    G["Threat Intel Engine"] --> E
    H["Signature Engine"] --> E
    I["ML Anomaly Engine"] --> E
```

## Important Files

- `main.py`: CLI entry point for test, run, stats, and console modes.
- `desktop_app.py`: Standalone Windows desktop app wrapper with embedded dashboard window.
- `run_live.py`: One-command local service that starts the pipeline and dashboard.
- `run_api.py`: REST API launcher.
- `manage.py`: Operator CLI for start, stop, status, doctor, demo, test, logs, and dashboard open.
- `config/deployment_profiles.json`: Dev, demo, offline, and production deployment profiles.
- `config/deployment.py`: Profile loading and environment helpers.
- `docs/ENTERPRISE_DEPLOYMENT.md`: Enterprise service, collector, and installer guide.
- `core/pipeline.py`: Multi-threaded engine orchestration.
- `core/collectors/win_eventlog.py`: Live Windows Event Log and Sysmon collector.
- `core/collectors/pcap_live.py`: Live packet metadata collector using Scapy/Npcap.
- `core/collectors/manager.py`: Collector lifecycle and readiness checks.
- `core/models/event_models.py`: Normalized event, entity, and cluster schemas.
- `core/models/behavior_models.py`: Behavioral profiles, patterns, and known attack signatures.
- `core/engines/behavior_engine.py`: Profile updates, attack matching, profile persistence.
- `core/sensor_parsers.py`: Production telemetry parser and sensor auto-detection.
- `core/attack_timeline.py`: MITRE ATT&CK timeline and investigation report helpers.
- `interfaces/dashboard.py`: Streamlit analyst dashboard.
- `run_dashboard.py`: Dashboard launcher.
- `scripts/generate_sample_data.py`: Local synthetic telemetry generator.
- `scripts/simulate_live_alerts.py`: Writes pipeline-shaped alerts into the live alert store.
- `scripts/install_app.ps1`: Per-user Windows app installer with Start Menu/Desktop shortcuts.
- `scripts/uninstall_app.ps1`: Removes the installed Windows app and shortcuts.
- `scripts/open_dashboard.ps1`: Shortcut target that starts the app and opens the dashboard.
- `scripts/run_demo.ps1`: Shortcut target that injects a demo scenario.
- `scripts/start_service.ps1`: Windows operator start script.
- `scripts/status_service.ps1`: Windows operator status/report script.
- `scripts/stop_service.ps1`: Windows operator stop script.
- `scripts/install_windows_task.ps1`: Optional Windows Task Scheduler installer.
- `scripts/uninstall_windows_task.ps1`: Removes the scheduled task.
- `scripts/install_windows_service.ps1`: Installs Cyber-EW as a Windows Service.
- `scripts/uninstall_windows_service.ps1`: Removes the Windows Service.
- `scripts/build_exe.ps1`: Builds PyInstaller executable and optional Inno Setup installer.
- `scripts/install_sysmon.ps1`: Optional helper for installing a local Sysmon executable.
- `packaging/cyber_ew_fusion_cell.spec`: PyInstaller build definition.
- `packaging/cyber-ew-fusion-cell.iss`: Inno Setup installer definition.
- `storage/alert_store.py`: Durable JSONL alert store used by the pipeline and dashboard.
- `storage/soc_store.py`: Local case, IOC, and audit stores.
- `.env.example`: Optional environment variables for API key and ports.

## Professional Workflow

The intended operating model is:

1. Launch the installed Cyber-EW Fusion Cell desktop app, or run `run_live.py` for service/server deployments.
2. Feed JSON, Suricata, Zeek, or Windows/Sysmon telemetry into `data/inputs/live/`.
3. Use `manage.py demo` when you need a repeatable ransomware/C2/lateral-movement exercise.
4. Review deduplicated high-risk alerts in the dashboard.
5. Open cases, assign owners, set disposition, and follow response playbooks.
6. Add confirmed bad IPs/domains/users/files to the IOC watchlist.
7. Use the ATT&CK investigation timeline to explain the attack chain.
8. Use the hunt workspace to pivot across entities and export evidence.
9. Run `manage.py report --profile production` for deployment/security readiness.
10. Run `manage.py cleanup --profile production` on a retention schedule.
11. Use `/export/bundle`, `/attack/timeline`, or the dashboard SOC bundle export for handoff/reporting.

## Notes

This repository contains many `- Copy` files and repair scripts from earlier iterations. The live implementation uses the non-copy source files under `core/`, `config/`, `utils/`, `interfaces/`, `storage/`, `main.py`, and `run_system.py`.
