"""
SOC workflow storage for cases, analyst audit actions, and local IOCs.

The project is designed to run in small or air-gapped environments, so these
stores use JSON/JSONL files instead of requiring a database server.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import CONFIG


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, fallback: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    return fallback


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


class AuditLog:
    """Append-only analyst action log."""

    def __init__(self, path: Optional[Path | str] = None):
        self.path = Path(path) if path else CONFIG.data_dir / "outputs" / "audit_log.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, action: str, target: str, details: Optional[Dict[str, Any]] = None, actor: str = "local-analyst") -> None:
        record = {
            "timestamp": utc_now(),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details or {},
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str))
                f.write("\n")

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        records: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        records.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return records[:limit]


class CaseStore:
    """Persistent alert case workflow."""

    def __init__(self, path: Optional[Path | str] = None, audit_log: Optional[AuditLog] = None):
        self.path = Path(path) if path else CONFIG.data_dir / "outputs" / "cases.json"
        self.audit_log = audit_log or AuditLog()
        self._lock = threading.Lock()

    def all(self) -> List[Dict[str, Any]]:
        payload = read_json(self.path, {"cases": []})
        cases = payload.get("cases", []) if isinstance(payload, dict) else []
        return cases if isinstance(cases, list) else []

    def by_alert_id(self) -> Dict[str, Dict[str, Any]]:
        return {case.get("alert_id", ""): case for case in self.all() if case.get("alert_id")}

    def get(self, case_id: str) -> Optional[Dict[str, Any]]:
        return next((case for case in self.all() if case.get("case_id") == case_id), None)

    def upsert_for_alert(
        self,
        alert_id: str,
        alert: Dict[str, Any],
        status: str = "New",
        owner: str = "",
        notes: str = "",
        disposition: str = "Undetermined",
        playbook: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            cases = self.all()
            now = utc_now()
            case = next((item for item in cases if item.get("alert_id") == alert_id), None)
            if not case:
                case = {
                    "case_id": f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
                    "alert_id": alert_id,
                    "created_at": now,
                    "history": [],
                }
                cases.append(case)

            old_status = case.get("status", "New")
            case.update(
                {
                    "updated_at": now,
                    "status": status,
                    "owner": owner,
                    "notes": notes,
                    "disposition": disposition,
                    "playbook": playbook,
                    "tags": tags or [],
                    "severity": str(alert.get("level", alert.get("threat_level", "Unknown"))),
                    "score": float(alert.get("score", alert.get("threat_score", {}).get("score", 0.0)) or 0.0),
                    "source_ip": alert.get("source_ip", ""),
                    "destination_ip": alert.get("destination_ip", ""),
                    "patterns": alert.get("patterns", ""),
                }
            )
            case.setdefault("history", []).append(
                {
                    "timestamp": now,
                    "from_status": old_status,
                    "to_status": status,
                    "owner": owner,
                    "disposition": disposition,
                }
            )
            atomic_write_json(self.path, {"cases": cases})
            self.audit_log.append("case.upsert", case["case_id"], {"alert_id": alert_id, "status": status})
            return case

    def summary(self) -> Dict[str, Any]:
        cases = self.all()
        open_statuses = {"New", "Investigating", "Contained"}
        by_status: Dict[str, int] = {}
        for case in cases:
            status = case.get("status", "New")
            by_status[status] = by_status.get(status, 0) + 1
        return {
            "total_cases": len(cases),
            "open_cases": sum(1 for case in cases if case.get("status", "New") in open_statuses),
            "by_status": by_status,
        }


class IOCStore:
    """Local indicator watchlist backed by data/threat_intel/local_iocs.json."""

    def __init__(self, path: Optional[Path | str] = None, audit_log: Optional[AuditLog] = None):
        self.path = Path(path) if path else CONFIG.data_dir / "threat_intel" / "local_iocs.json"
        self.audit_log = audit_log or AuditLog()
        self._lock = threading.Lock()

    def all(self) -> List[Dict[str, Any]]:
        records = read_json(self.path, [])
        return records if isinstance(records, list) else []

    def add(
        self,
        value: str,
        ioc_type: str,
        threat_type: str = "watchlist",
        confidence: float = 0.7,
        description: str = "",
        tags: Optional[List[str]] = None,
        source: str = "analyst",
    ) -> Dict[str, Any]:
        value = value.strip()
        ioc_type = ioc_type.strip().lower()
        if not value:
            raise ValueError("IOC value is required")

        with self._lock:
            records = self.all()
            existing = next(
                (item for item in records if str(item.get("value", "")).lower() == value.lower() and str(item.get("ioc_type", "")).lower() == ioc_type),
                None,
            )
            now = utc_now()
            if existing:
                existing.update(
                    {
                        "last_seen": now,
                        "threat_type": threat_type or existing.get("threat_type", "watchlist"),
                        "confidence": max(0.0, min(1.0, float(confidence))),
                        "description": description or existing.get("description", ""),
                        "tags": tags or existing.get("tags", []),
                        "source": source or existing.get("source", "analyst"),
                    }
                )
                record = existing
            else:
                record = {
                    "value": value,
                    "ioc_type": ioc_type,
                    "threat_type": threat_type,
                    "source": source,
                    "confidence": max(0.0, min(1.0, float(confidence))),
                    "first_seen": now,
                    "last_seen": now,
                    "description": description,
                    "tags": tags or [],
                }
                records.append(record)

            atomic_write_json(self.path, records)
            self.audit_log.append("ioc.upsert", value, {"ioc_type": ioc_type, "threat_type": threat_type})
            return record

    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = {
            str(event.get("source_ip", "")).lower(),
            str(event.get("destination_ip", "")).lower(),
            str(event.get("username", "")).lower(),
            str(event.get("file_path", "")).lower(),
        }
        details = event.get("details", {})
        if isinstance(details, dict):
            for value in details.values():
                if isinstance(value, str):
                    candidates.add(value.lower())
                elif isinstance(value, list):
                    candidates.update(str(item).lower() for item in value)

        matches = []
        for ioc in self.all():
            value = str(ioc.get("value", "")).lower()
            if value and any(value in candidate for candidate in candidates):
                matches.append(ioc)
        return matches

    def stats(self) -> Dict[str, Any]:
        records = self.all()
        by_type: Dict[str, int] = {}
        by_threat: Dict[str, int] = {}
        for record in records:
            by_type[record.get("ioc_type", "unknown")] = by_type.get(record.get("ioc_type", "unknown"), 0) + 1
            by_threat[record.get("threat_type", "unknown")] = by_threat.get(record.get("threat_type", "unknown"), 0) + 1
        return {"total_iocs": len(records), "by_type": by_type, "by_threat": by_threat}
