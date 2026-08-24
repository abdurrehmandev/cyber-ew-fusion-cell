"""Connector catalog and Sentinel-style connector framework metadata."""
from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, List

from core.capability_center import connector_readiness


@dataclass(frozen=True)
class ConnectorDefinition:
    name: str
    category: str
    mode: str
    status: str
    auth: str
    description: str


LOCAL_CONNECTORS = [
    ConnectorDefinition("Windows Event Log", "Endpoint", "Live", "Implemented", "Local admin", "Polls System, Application, Security, and Sysmon channels."),
    ConnectorDefinition("Sysmon", "Endpoint", "Live", "Implemented", "Local admin", "High-fidelity process, network, registry, and file telemetry when Sysmon is installed."),
    ConnectorDefinition("Npcap packet capture", "Network", "Live", "Implemented", "Local admin + Npcap", "Captures local packet metadata with BPF filtering."),
    ConnectorDefinition("Syslog UDP 514", "Network", "Live", "Implemented", "Firewall rule", "Receives firewall, VPN, Linux, router, and appliance logs."),
    ConnectorDefinition("JSON/JSONL drop folder", "Custom", "Batch/Live", "Implemented", "Filesystem", "Ingests local JSON, JSONL, EVE, Zeek TSV, and log files."),
    ConnectorDefinition("Local IOC watchlist", "Threat Intel", "Local", "Implemented", "Filesystem", "Local indicator list with matching and case enrichment."),
    ConnectorDefinition("ThreatFox feed", "Threat Intel", "Feed", "Implemented", "Internet optional", "Pulls community malware indicators when network access is allowed."),
]


DEMO_CONNECTORS = [
    ConnectorDefinition("Microsoft 365", "SaaS", "API", "Demo connector", "Graph API OAuth", "Blueprint for Exchange, SharePoint, and audit activity ingestion."),
    ConnectorDefinition("Microsoft Entra ID", "Identity", "API", "Demo connector", "Graph API OAuth", "Blueprint for sign-ins, risky users, and audit logs."),
    ConnectorDefinition("Microsoft Defender for Endpoint", "XDR", "API", "Demo connector", "Defender API", "Blueprint for device alerts, incidents, and isolation actions."),
    ConnectorDefinition("Microsoft Defender for Cloud", "Cloud", "API", "Demo connector", "Azure credential", "Blueprint for cloud security posture and workload alerts."),
    ConnectorDefinition("AWS CloudTrail", "Cloud", "S3/API", "Demo connector", "AWS IAM", "Blueprint for account activity and management events."),
    ConnectorDefinition("AWS GuardDuty", "Cloud", "API", "Demo connector", "AWS IAM", "Blueprint for GuardDuty findings."),
    ConnectorDefinition("GCP Cloud Logging", "Cloud", "Pub/Sub", "Demo connector", "Service account", "Blueprint for Google Cloud audit and workload logs."),
    ConnectorDefinition("Okta", "Identity", "API", "Demo connector", "API token", "Blueprint for identity provider sign-in and risk events."),
    ConnectorDefinition("CrowdStrike Falcon", "EDR", "API", "Demo connector", "OAuth client", "Blueprint for EDR detections and host containment."),
    ConnectorDefinition("Palo Alto Firewall", "Network", "Syslog/API", "Demo connector", "Syslog/API key", "Blueprint for traffic, threat, and URL filtering logs."),
    ConnectorDefinition("Fortinet FortiGate", "Network", "Syslog/API", "Demo connector", "Syslog/API key", "Blueprint for firewall and VPN events."),
    ConnectorDefinition("Cisco ASA/Firepower", "Network", "Syslog/API", "Demo connector", "Syslog/API key", "Blueprint for firewall and IDS events."),
    ConnectorDefinition("Linux auditd", "Endpoint", "Syslog/File", "Demo connector", "Syslog/SSH", "Blueprint for Linux audit events."),
    ConnectorDefinition("Zeek", "Network", "File", "Demo connector", "Filesystem", "Blueprint for Zeek conn, dns, http, ssl, and files logs."),
    ConnectorDefinition("Suricata EVE", "Network", "File", "Demo connector", "Filesystem", "Blueprint for Suricata IDS events."),
    ConnectorDefinition("ServiceNow", "ITSM", "API", "Demo connector", "API credential", "Blueprint for ticket creation and case synchronization."),
    ConnectorDefinition("Jira", "ITSM", "API", "Demo connector", "API token", "Blueprint for issue creation and status sync."),
    ConnectorDefinition("Slack", "Notification", "Webhook", "Demo connector", "Webhook", "Blueprint for analyst notifications."),
    ConnectorDefinition("Microsoft Teams", "Notification", "Webhook", "Demo connector", "Webhook", "Blueprint for Teams incident notifications."),
    ConnectorDefinition("STIX/TAXII", "Threat Intel", "API", "Demo connector", "TAXII credential", "Blueprint for structured threat intel ingestion."),
]


def connector_catalog() -> List[Dict[str, Any]]:
    readiness = {item["connector"]: item for item in connector_readiness()}
    rows = [asdict(item) for item in LOCAL_CONNECTORS + DEMO_CONNECTORS]
    for row in rows:
        probe = readiness.get(row["name"])
        if probe:
            row["readiness"] = probe.get("status", "")
            row["detail"] = probe.get("detail", "")
        else:
            row["readiness"] = "Requires credentials" if row["status"] == "Demo connector" else "Ready"
            row["detail"] = row["description"]
    return rows


def connector_summary() -> Dict[str, Any]:
    rows = connector_catalog()
    return {
        "total_connectors": len(rows),
        "implemented": sum(1 for row in rows if row["status"] == "Implemented"),
        "demo_blueprints": sum(1 for row in rows if row["status"] == "Demo connector"),
        "cloud_credentials_configured": bool(os.environ.get("CYBER_EW_CLOUD_CONNECTORS_ENABLED")),
        "categories": sorted({row["category"] for row in rows}),
    }

