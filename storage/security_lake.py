"""Local two-tier security lake and lightweight hunting query layer."""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from config.settings import CONFIG


DEFAULT_TABLES = {
    "alerts": "outputs/alerts.jsonl",
    "audit": "outputs/audit_log.jsonl",
    "cases": "outputs/cases.json",
    "iocs": "threat_intel/local_iocs.json",
}


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    return fallback


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _flatten(value: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, dict):
            flattened.update(_flatten(item, name))
        elif isinstance(item, list):
            flattened[name] = ", ".join(json.dumps(entry, default=str) if isinstance(entry, dict) else str(entry) for entry in item)
        else:
            flattened[name] = item
    return flattened


def _normalize_alert(record: Dict[str, Any]) -> Dict[str, Any]:
    event = record.get("event", {}) if isinstance(record.get("event"), dict) else {}
    threat = record.get("threat_score", {}) if isinstance(record.get("threat_score"), dict) else {}
    return {
        "timestamp": record.get("timestamp") or event.get("timestamp"),
        "table": "alerts",
        "id": record.get("alert_id") or event.get("event_id"),
        "level": str(record.get("threat_level") or threat.get("level") or event.get("severity") or "").lower(),
        "score": float(threat.get("score", record.get("score", 0.0)) or 0.0),
        "event_type": event.get("event_type", record.get("event_type", "")),
        "source_ip": event.get("source_ip", record.get("source_ip", "")),
        "destination_ip": event.get("destination_ip", record.get("destination_ip", "")),
        "username": event.get("username", record.get("username", "")),
        "process_name": event.get("process_name", record.get("process_name", "")),
        "patterns": ", ".join(str(item.get("pattern_type", item)) for item in record.get("behavior_analysis", {}).get("patterns", []) if item) if isinstance(record.get("behavior_analysis"), dict) else record.get("patterns", ""),
        "raw": json.dumps(record, default=str),
    }


class SecurityLake:
    """Two-tier local storage facade.

    The analytics tier is the current JSON/JSONL operational store. The lake tier
    is optional Parquet snapshots for long-term retention and export.
    """

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        self.data_dir = Path(data_dir) if data_dir else CONFIG.data_dir
        self.analytics_dir = self.data_dir / "outputs"
        self.lake_dir = self.data_dir / "lake"
        self.lake_dir.mkdir(parents=True, exist_ok=True)

    def table_records(self, table: str, limit: int = 5000) -> List[Dict[str, Any]]:
        table = table.lower().strip() or "alerts"
        if table == "alerts":
            records = [_normalize_alert(item) for item in _read_jsonl(self.data_dir / DEFAULT_TABLES["alerts"])]
        elif table == "audit":
            records = [dict(item, table="audit") for item in _read_jsonl(self.data_dir / DEFAULT_TABLES["audit"])]
        elif table == "cases":
            payload = _read_json(self.data_dir / DEFAULT_TABLES["cases"], {"cases": []})
            records = [dict(item, table="cases") for item in payload.get("cases", [])] if isinstance(payload, dict) else []
        elif table == "iocs":
            payload = _read_json(self.data_dir / DEFAULT_TABLES["iocs"], [])
            records = [dict(item, table="iocs") for item in payload] if isinstance(payload, list) else []
        else:
            records = []
        records.sort(key=lambda item: str(item.get("timestamp") or item.get("updated_at") or item.get("last_seen") or ""), reverse=True)
        return records[: max(1, min(limit, 20000))]

    def all_records(self, limit_per_table: int = 2500) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for table in DEFAULT_TABLES:
            records.extend(self.table_records(table, limit=limit_per_table))
        return records

    def stats(self) -> Dict[str, Any]:
        table_counts = {table: len(self.table_records(table, limit=1_000_000)) for table in DEFAULT_TABLES}
        parquet_files = list(self.lake_dir.rglob("*.parquet"))
        return {
            "analytics_tier": str(self.analytics_dir),
            "lake_tier": str(self.lake_dir),
            "tables": table_counts,
            "parquet_files": len(parquet_files),
            "parquet_bytes": sum(path.stat().st_size for path in parquet_files if path.exists()),
        }

    def snapshot_to_lake(self) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results: Dict[str, Any] = {"created_at": timestamp, "tables": {}}
        for table in DEFAULT_TABLES:
            records = self.table_records(table, limit=1_000_000)
            if not records:
                results["tables"][table] = {"records": 0, "path": ""}
                continue
            target = self.lake_dir / table / f"{table}_{timestamp}.parquet"
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                pd.DataFrame(records).to_parquet(target, index=False)
                results["tables"][table] = {"records": len(records), "path": str(target)}
            except Exception as exc:
                fallback = target.with_suffix(".jsonl")
                fallback.write_text("\n".join(json.dumps(item, default=str) for item in records), encoding="utf-8")
                results["tables"][table] = {"records": len(records), "path": str(fallback), "warning": str(exc)}
        return results


class HuntingQueryEngine:
    """Small KQL-like query engine for local records.

    Supported examples:
    - alerts | where level == "high" | take 50
    - alerts | search "192.168.1.10" | project timestamp,level,source_ip
    - alerts | where score >= 0.7 | summarize count by source_ip
    """

    def __init__(self, lake: Optional[SecurityLake] = None) -> None:
        self.lake = lake or SecurityLake()

    def execute(self, query: str, limit: int = 500) -> Dict[str, Any]:
        started = datetime.now(timezone.utc)
        query = (query or "alerts | take 100").strip()
        parts = [part.strip() for part in query.split("|") if part.strip()]
        table = parts[0].lower() if parts else "alerts"
        records = self.lake.all_records() if table in {"*", "all", "union"} else self.lake.table_records(table, limit=20000)
        projected: Optional[List[str]] = None

        for command in parts[1:]:
            lower = command.lower()
            if lower.startswith("where "):
                records = self._where(records, command[6:].strip())
            elif lower.startswith("search "):
                term = command[7:].strip().strip('"').strip("'").lower()
                records = [item for item in records if term in json.dumps(item, default=str).lower()]
            elif lower.startswith("project "):
                projected = [part.strip() for part in command[8:].split(",") if part.strip()]
            elif lower.startswith("take ") or lower.startswith("limit "):
                count = int(re.findall(r"\d+", command)[0]) if re.findall(r"\d+", command) else limit
                records = records[: max(1, min(count, 2000))]
            elif lower.startswith("summarize "):
                records = self._summarize(records, command)

        if projected:
            records = [{field: item.get(field, item.get(field.replace(".", "_"), "")) for field in projected} for item in records]
        records = records[: max(1, min(limit, 2000))]
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        return {
            "query": query,
            "rows": records,
            "row_count": len(records),
            "elapsed_ms": elapsed_ms,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _where(self, records: List[Dict[str, Any]], expression: str) -> List[Dict[str, Any]]:
        match = re.match(r"([\w.]+)\s*(==|!=|>=|<=|>|<|contains)\s*(.+)", expression, flags=re.IGNORECASE)
        if not match:
            return records
        field, op, raw_value = match.groups()
        expected = raw_value.strip().strip('"').strip("'")

        def value_of(item: Dict[str, Any]) -> Any:
            if field in item:
                return item[field]
            flattened = _flatten(item)
            return flattened.get(field, "")

        def compare(item: Dict[str, Any]) -> bool:
            actual = value_of(item)
            if op.lower() == "contains":
                return expected.lower() in str(actual).lower()
            if op in {"==", "!="}:
                result = str(actual).lower() == expected.lower()
                return result if op == "==" else not result
            try:
                actual_number = float(actual or 0)
                expected_number = float(expected)
            except Exception:
                return False
            if op == ">=":
                return actual_number >= expected_number
            if op == "<=":
                return actual_number <= expected_number
            if op == ">":
                return actual_number > expected_number
            if op == "<":
                return actual_number < expected_number
            return False

        return [item for item in records if compare(item)]

    def _summarize(self, records: List[Dict[str, Any]], command: str) -> List[Dict[str, Any]]:
        match = re.search(r"by\s+([\w.]+)", command, flags=re.IGNORECASE)
        if not match:
            return [{"count": len(records)}]
        field = match.group(1)
        counts = Counter(str(item.get(field, "")) for item in records)
        return [{field: key, "count": value} for key, value in counts.most_common(250)]

