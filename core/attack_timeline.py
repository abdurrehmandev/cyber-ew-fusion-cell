"""
MITRE ATT&CK-style investigation timeline helpers.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


ATTACK_RULES = [
    {
        "keywords": ("credential", "brute", "stuffing", "failed login", "password"),
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "phase": 1,
    },
    {
        "keywords": ("privilege", "schtasks", "scheduled task", "runas", "uac", "token"),
        "tactic": "Privilege Escalation",
        "technique_id": "T1053",
        "technique": "Scheduled Task/Job",
        "phase": 2,
    },
    {
        "keywords": ("lateral", "smb", "rdp", "remote service", "port 445", "3389"),
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique": "Remote Services",
        "phase": 3,
    },
    {
        "keywords": ("c2", "beacon", "callback", "command and control", "periodic"),
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "phase": 4,
    },
    {
        "keywords": ("staging", "archive", "7z", ".zip", ".rar", ".tar", "compress"),
        "tactic": "Collection",
        "technique_id": "T1074",
        "technique": "Data Staged",
        "phase": 5,
    },
    {
        "keywords": ("exfil", "large outbound", "transfer", "upload"),
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "phase": 6,
    },
    {
        "keywords": ("ransomware", "encrypt", ".locked", ".crypt", ".encrypted"),
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "phase": 7,
    },
]


def build_attack_timeline(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Classify records and return ordered ATT&CK timeline entries."""
    timeline = []
    for record in records:
        flattened = flatten_record(record)
        classification = classify_attack(flattened)
        if not classification:
            continue
        timeline.append({**flattened, **classification, "evidence": evidence_text(flattened)})

    return sorted(timeline, key=lambda item: (safe_timestamp(item.get("timestamp")), item.get("phase", 99)))


def build_investigation_report(records: Iterable[Dict[str, Any]], scope: str = "") -> Dict[str, Any]:
    """Build a portable analyst report from timeline records."""
    timeline = build_attack_timeline(records)
    tactics = Counter(item["tactic"] for item in timeline)
    techniques = Counter(f"{item['technique_id']} {item['technique']}" for item in timeline)
    entities = sorted(
        {
            value
            for item in timeline
            for value in (item.get("source_ip"), item.get("destination_ip"), item.get("username"), item.get("process_name"))
            if value
        }
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope or "all telemetry",
        "summary": {
            "timeline_events": len(timeline),
            "tactics": dict(tactics),
            "techniques": dict(techniques),
            "entities": entities,
            "first_seen": timeline[0]["timestamp"] if timeline else None,
            "last_seen": timeline[-1]["timestamp"] if timeline else None,
        },
        "timeline": timeline,
    }


def classify_attack(record: Dict[str, Any]) -> Dict[str, Any]:
    text = searchable_text(record)
    for rule in ATTACK_RULES:
        if any(keyword in text for keyword in rule["keywords"]):
            return {
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique": rule["technique"],
                "phase": rule["phase"],
            }
    return {}


def flatten_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Accept dashboard rows, raw events, or persisted alert records."""
    source = record.get("event", record) if isinstance(record.get("event"), dict) else record
    score = record.get("score")
    if score is None and isinstance(record.get("threat_score"), dict):
        score = record["threat_score"].get("score")

    patterns = record.get("patterns")
    if not patterns and isinstance(record.get("behavior_analysis"), dict):
        patterns = ", ".join(
            str(item.get("description") or item.get("pattern_type", ""))
            for item in record["behavior_analysis"].get("patterns", [])
            if isinstance(item, dict)
        )

    details = source.get("details", {}) if isinstance(source.get("details"), dict) else {}
    return {
        "event_id": record.get("alert_id") or source.get("event_id") or record.get("event_id") or "",
        "timestamp": source.get("timestamp") or record.get("timestamp") or "",
        "level": str(record.get("level") or record.get("threat_level") or source.get("severity") or "").title(),
        "score": float(score or 0.0),
        "patterns": patterns or "",
        "event_type": source.get("event_type") or "",
        "source_ip": source.get("source_ip") or "",
        "destination_ip": source.get("destination_ip") or "",
        "username": source.get("username") or "",
        "process_name": source.get("process_name") or "",
        "file_path": source.get("file_path") or details.get("file_path") or "",
        "port": source.get("port") or details.get("port") or "",
        "details": details,
    }


def searchable_text(record: Dict[str, Any]) -> str:
    fields = [
        record.get("patterns", ""),
        record.get("event_type", ""),
        record.get("process_name", ""),
        record.get("file_path", ""),
        str(record.get("port", "")),
        str(record.get("details", "")),
    ]
    return " ".join(fields).lower()


def evidence_text(record: Dict[str, Any]) -> str:
    pieces = [
        record.get("patterns"),
        record.get("process_name"),
        record.get("file_path"),
        record.get("source_ip"),
        record.get("destination_ip"),
    ]
    return " | ".join(str(item) for item in pieces if item)


def safe_timestamp(value: Any) -> datetime:
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)
