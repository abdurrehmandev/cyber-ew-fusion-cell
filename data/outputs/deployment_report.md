# Cyber-EW Deployment Report

- Generated: 2026-05-31T20:46:38.633642+00:00
- Profile: production
- Dashboard: http://127.0.0.1:8501
- API: http://127.0.0.1:8080

## Security Checks

- PASS: Local-only binding - Bind host is 127.0.0.1
- PASS: API key for hardened profile - API key is required by this profile
- PASS: Dashboard port - http://127.0.0.1:8501
- PASS: API port - http://127.0.0.1:8080
- PASS: Retention policy - alerts=365d logs=180d inputs=30d
- PASS: Disk free - 353.63 GB free at C:\Users\rehma\OneDrive\Documents\cyber-ew-fusion-cell

## Sensor Checks

- Windows Event Log: available (2/4 channels readable)
- Sysmon channel: not detected
- Packet capture: available; libpcap/Npcap: not detected (37 interfaces)

## Service

- API health: ok
- Live service: True
