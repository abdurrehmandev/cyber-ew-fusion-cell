"""Local capability and deployment readiness helpers.

This module keeps the dashboard honest about what is live, what is demo-only,
and what needs administrator or third-party setup before production use.
"""
from __future__ import annotations

import ctypes
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from config.settings import CONFIG
from core.collectors.manager import collector_readiness


SENTINEL_CAPABILITY_MAP = [
    {
        "capability": "SIEM analytics",
        "benchmark": "Cloud-native SIEM with SOAR, UEBA, TI, and AI.",
        "local": "Local ingestion, normalization, correlation, scoring, cases, alerts, and reports.",
        "status": "Active",
    },
    {
        "capability": "Cost-efficient data lake",
        "benchmark": "Centralized scalable security data lake.",
        "local": "Local JSON/JSONL alert lake under the Cyber-EW application data folder.",
        "status": "Active",
    },
    {
        "capability": "Graph-powered context",
        "benchmark": "Security graph across users, hosts, clouds, and workloads.",
        "local": "Entity pivots, communication pairs, behavior profiles, and ATT&CK timeline.",
        "status": "Partial",
    },
    {
        "capability": "MCP and agent interface",
        "benchmark": "Reasoning layer for agents to discover and invoke platform tasks.",
        "local": "Local API endpoints and planned MCP-compatible task facade.",
        "status": "Demo",
    },
    {
        "capability": "Native XDR integration",
        "benchmark": "Unified SIEM and XDR across Microsoft Defender.",
        "local": "Windows Event Log, Sysmon, Npcap packet capture, local IOCs, and file telemetry.",
        "status": "Partial",
    },
    {
        "capability": "Enterprise connectors",
        "benchmark": "350+ native connectors and codeless connector framework.",
        "local": "JSON, JSONL, syslog, Windows Event Log, Sysmon, PCAP/Npcap, CSV/log imports.",
        "status": "Partial",
    },
    {
        "capability": "SOC optimization",
        "benchmark": "AI-driven recommendations and operational best practices.",
        "local": "Readiness checks, response playbooks, queue health, and recommended actions.",
        "status": "Active",
    },
    {
        "capability": "Generative AI assistant",
        "benchmark": "Security Copilot for summaries, queries, and response guidance.",
        "local": "Offline templates now; optional cloud AI connector can be configured later.",
        "status": "Demo",
    },
    {
        "capability": "Threat intelligence",
        "benchmark": "Microsoft and third-party CTI, STIX/TAXII, enrichment, and hunting.",
        "local": "Local IOC watchlist, ThreatFox feed, YARA rules, and exportable evidence bundles.",
        "status": "Active",
    },
]


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def operation_mode() -> str:
    return os.environ.get("CYBER_EW_OPERATION_MODE", "demo").strip().lower() or "demo"


def mock_telemetry_enabled() -> bool:
    disabled = os.environ.get("CYBER_EW_DISABLE_MOCK_SOURCES", "").lower() in {"1", "true", "yes", "on"}
    explicit = os.environ.get("CYBER_EW_ENABLE_MOCK_TELEMETRY")
    if explicit is not None:
        return explicit.lower() in {"1", "true", "yes", "on"}
    return not disabled


def _status_label(ready: bool, partial: bool = False) -> str:
    if ready:
        return "Ready"
    if partial:
        return "Needs attention"
    return "Not ready"


def _udp_port_status(port: int = 514) -> Dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
        return {
            "ready": False,
            "detail": f"UDP {port} is free; no listener is currently bound.",
        }
    except OSError as exc:
        return {
            "ready": True,
            "detail": f"UDP {port} appears occupied by a listener or protected by the OS: {exc}",
        }
    finally:
        sock.close()


def connector_readiness(service: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    service = service or {}
    pipeline = service.get("pipeline", {}) if isinstance(service, dict) else {}
    engine_stats = pipeline.get("engine_stats", {}) if isinstance(pipeline, dict) else {}
    collector_stats = engine_stats.get("collector_manager", {}) if isinstance(engine_stats, dict) else {}
    readiness = collector_readiness()

    eventlog = readiness.get("windows_eventlog", {})
    channels = eventlog.get("channels", {}) if isinstance(eventlog, dict) else {}
    security = channels.get("Security", {}) if isinstance(channels, dict) else {}
    sysmon = readiness.get("sysmon", {})
    pcap = readiness.get("pcap_live", {})
    syslog = _udp_port_status(514)

    rows = [
        {
            "connector": "Administrator access",
            "status": _status_label(is_admin()),
            "mode": "Required for Security log, Sysmon install, packet capture, and firewall changes.",
            "detail": "Running elevated" if is_admin() else "Restart the app as administrator for full host visibility.",
        },
        {
            "connector": "Windows Event Logs",
            "status": _status_label(bool(eventlog.get("available")), partial=bool(channels)),
            "mode": "Live local collector",
            "detail": f"{sum(1 for item in channels.values() if item.get('available'))}/{len(channels) or 4} channels readable.",
        },
        {
            "connector": "Windows Security log",
            "status": _status_label(bool(security.get("available"))),
            "mode": "Privilege-sensitive live source",
            "detail": security.get("error", "Security channel readable."),
        },
        {
            "connector": "Sysmon",
            "status": _status_label(bool(sysmon.get("installed"))),
            "mode": "High-fidelity endpoint telemetry",
            "detail": "Sysmon channel readable." if sysmon.get("installed") else "Install Microsoft Sysmon and a vetted config.",
        },
        {
            "connector": "Npcap packet capture",
            "status": _status_label(bool(pcap.get("libpcap_available"))),
            "mode": "Live network metadata",
            "detail": pcap.get("npcap_hint", pcap.get("error", "Packet capture probe completed.")),
        },
        {
            "connector": "Syslog UDP 514",
            "status": _status_label(bool(syslog.get("ready"))),
            "mode": "Network appliance log receiver",
            "detail": syslog.get("detail", ""),
        },
        {
            "connector": "JSON drop folder",
            "status": _status_label((CONFIG.data_dir / "inputs" / "live").exists()),
            "mode": "Local file connector",
            "detail": str(CONFIG.data_dir / "inputs" / "live"),
        },
        {
            "connector": "Threat intelligence",
            "status": _status_label(bool(engine_stats.get("threat_intel_engine", {}).get("total_iocs", 0))),
            "mode": "Local IOC and feed enrichment",
            "detail": f"{engine_stats.get('threat_intel_engine', {}).get('total_iocs', 0)} IOCs loaded.",
        },
    ]

    live_windows = collector_stats.get("windows_eventlog", {}).get("events_emitted", 0)
    live_packets = collector_stats.get("pcap_live", {}).get("events_emitted", 0)
    for row in rows:
        if row["connector"] == "Windows Event Logs" and live_windows:
            row["detail"] = f"{live_windows} live events emitted this session."
        if row["connector"] == "Npcap packet capture" and live_packets:
            row["detail"] = f"{live_packets} packet events emitted this session."
    return rows


def runtime_mode_summary(service: Dict[str, Any] | None = None) -> Dict[str, str]:
    service = service or {}
    pipeline = service.get("pipeline", {}) if isinstance(service, dict) else {}
    engine_stats = pipeline.get("engine_stats", {}) if isinstance(pipeline, dict) else {}
    collectors = engine_stats.get("collector_manager", {}) if isinstance(engine_stats, dict) else {}

    windows_events = int(collectors.get("windows_eventlog", {}).get("events_emitted", 0) or 0)
    packet_events = int(collectors.get("pcap_live", {}).get("events_emitted", 0) or 0)
    generated = mock_telemetry_enabled()

    if generated and (windows_events or packet_events):
        label = "Hybrid demo/live"
        detail = "Generated telemetry is mixed with live collector readiness."
    elif generated:
        label = "Demo mode"
        detail = "Telemetry is generated or replayed for demonstration and training."
    elif windows_events or packet_events:
        label = "Production live"
        detail = "Telemetry is coming from live local collectors."
    else:
        label = "Live standby"
        detail = "Collectors are armed, but no live events have arrived yet."

    return {
        "label": label,
        "detail": detail,
        "operation_mode": operation_mode().title(),
        "mock_telemetry": "Enabled" if generated else "Disabled",
        "windows_events": str(windows_events),
        "packet_events": str(packet_events),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def capability_matrix(service: Dict[str, Any] | None = None) -> List[Dict[str, str]]:
    service = service or {}
    matrix = [dict(item) for item in SENTINEL_CAPABILITY_MAP]
    runtime = runtime_mode_summary(service)
    for item in matrix:
        if item["capability"] == "Enterprise connectors" and runtime["label"] in {"Demo mode", "Live standby"}:
            item["status"] = "Needs live source"
        if item["capability"] == "Native XDR integration" and runtime["windows_events"] == "0":
            item["status"] = "Needs live source"
    return matrix


def installer_action_plan() -> List[Dict[str, str]]:
    return [
        {
            "step": "Install with administrator privileges",
            "why": "Allows Security log access, Sysmon setup, packet capture, and firewall changes.",
            "local_action": "Run setup as administrator or launch the app as administrator.",
        },
        {
            "step": "Choose operation mode",
            "why": "Demo shows generated attacks; production disables mock telemetry.",
            "local_action": "Use the setup mode selection or registry profile.",
        },
        {
            "step": "Install Sysmon",
            "why": "Adds process, network, file, registry, and driver telemetry.",
            "local_action": "Install Microsoft Sysmon with a trusted config, then restart the app.",
        },
        {
            "step": "Install Npcap",
            "why": "Enables live packet metadata collection from local interfaces.",
            "local_action": "Install Npcap in WinPcap-compatible mode, then enable packet capture.",
        },
        {
            "step": "Forward syslog",
            "why": "Ingests firewall, router, VPN, Linux, and appliance events.",
            "local_action": "Point devices to this host on UDP 514 or use JSON drop-folder imports.",
        },
    ]

