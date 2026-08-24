# Cyber-EW Fusion Cell Enterprise Deployment

This guide covers the enterprise-finalized deployment path: live Windows
collectors, Windows Service mode, executable packaging, registry/environment
configuration, and deployment validation.

## Install As A Windows App

From the project folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_app.ps1 -Profile production -DesktopShortcut
```

Optional auto-start:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_app.ps1 -Profile production -DesktopShortcut -AutoStart
```

## Run As A Windows Service

Install and start the service:

```powershell
.\scripts\install_windows_service.ps1 -Start
```

Remove the service:

```powershell
.\scripts\uninstall_windows_service.ps1
```

Direct service commands are also available:

```powershell
python main.py install-service
python main.py start-service
python main.py stop-service
python main.py remove-service
```

## Live Collectors

Production and offline profiles enable Windows Event Log collection by default.
Packet capture is opt-in because it depends on Npcap/libpcap and may require
administrator privileges.

Enable or override collectors with environment variables:

```powershell
$env:CYBER_EW_ENABLE_EVENTLOG="1"
$env:CYBER_EW_EVENTLOG_CHANNELS="Security,System,Application,Microsoft-Windows-Sysmon/Operational"
$env:CYBER_EW_ENABLE_PCAP="1"
$env:CYBER_EW_PCAP_INTERFACE="Ethernet"
$env:CYBER_EW_PCAP_FILTER="ip and not broadcast"
python manage.py restart --profile production
```

Supported live collector modules:

- `core/collectors/win_eventlog.py`: Windows Event Log and Sysmon channel polling.
- `core/collectors/pcap_live.py`: Scapy/Npcap packet metadata capture.
- `core/collectors/manager.py`: collector lifecycle and readiness probes.

## Sysmon

Cyber-EW detects whether `Microsoft-Windows-Sysmon/Operational` is readable.
Install Sysmon separately from Microsoft Sysinternals, then run:

```powershell
.\scripts\install_sysmon.ps1 -SysmonExe C:\Tools\Sysmon64.exe -AcceptEula
```

You may pass a Sysmon config:

```powershell
.\scripts\install_sysmon.ps1 -SysmonExe C:\Tools\Sysmon64.exe -ConfigPath C:\Tools\sysmonconfig.xml -AcceptEula
```

## Registry Configuration

The runtime reads configuration in this order:

1. `config/settings.yaml`
2. Windows Registry
3. Environment variables

Supported registry keys:

```text
HKLM\Software\CyberEW\DataDir
HKLM\Software\CyberEW\LogDir
HKLM\Software\CyberEW\RetentionDays
HKLM\Software\CyberEW\EnableEventLog
HKLM\Software\CyberEW\EventLogChannels
HKLM\Software\CyberEW\EnablePacketCapture
HKLM\Software\CyberEW\PacketInterface
HKLM\Software\CyberEW\PacketBpfFilter
```

`HKCU\Software\CyberEW` is also checked, which is useful for per-user pilots.

## Build Standalone EXE

Install build dependencies:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

Build the standalone desktop executable with PyInstaller:

```powershell
.\scripts\build_exe.ps1 -SkipInstaller
```

The windowed desktop executable is written under `dist\`.

## Build Setup.exe

Install Inno Setup 6, then run:

```powershell
winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
```

Build the installer:

```powershell
.\scripts\build_exe.ps1
```

The setup output is written under:

```text
dist\installer\
```

The Start Menu/Desktop shortcut launches Cyber-EW Fusion Cell as a standalone
desktop application with the dashboard embedded in the app window. The installer
does not create a Windows startup entry.

The Inno Setup script is:

```text
packaging\cyber-ew-fusion-cell.iss
```

## Deployment Validation

Run:

```powershell
python manage.py doctor --profile production
python manage.py report --profile production
python manage.py test
```

The doctor checks:

- Python dependency readiness
- Dashboard/API ports
- Windows Event Log channel access
- Sysmon channel availability
- Scapy/Npcap packet capture readiness
- Disk free space
- Writable data/log directories

Reports are written to:

```text
data\outputs\operator_health.json
data\outputs\deployment_report.json
data\outputs\deployment_report.md
```

## Pilot Deployment Notes

- Run production profile for SOC pilots.
- Keep API bound to `127.0.0.1` unless a reverse proxy and authentication layer are added.
- Use `CYBER_EW_API_KEY` or the generated `data\outputs\cyber_ew_api_key.txt` for mutating API calls.
- Enable packet capture only on hosts with Npcap installed and approved capture policy.
- Use `manage.py cleanup --profile production` as a scheduled retention task.
