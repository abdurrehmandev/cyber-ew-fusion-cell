"""
Durable alert storage for Cyber-EW Fusion Cell.

Alerts are stored as JSON Lines so the pipeline can append quickly while the
dashboard reads recent records without requiring a database service.
"""
from __future__ import annotations

import json
import hashlib
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import CONFIG


class AlertStore:
    """Append-only JSONL alert store."""

    def __init__(self, path: Optional[Path | str] = None):
        self.path = Path(path) if path else CONFIG.data_dir / "outputs" / "alerts.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, alert: Dict[str, Any]) -> bool:
        """Append one alert record.

        Returns False when the alert is already present in the store.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        dedupe_key = self._dedupe_key(alert)
        with self._lock:
            if dedupe_key and dedupe_key in self._existing_keys():
                return False
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(alert, default=str))
                f.write("\n")
        return True

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent alerts, newest first."""
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

        deduped: Dict[str, Dict[str, Any]] = {}
        for record in records:
            key = self._dedupe_key(record) or record.get("alert_id")
            if key and key not in deduped:
                deduped[key] = record

        result = list(deduped.values())
        result.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return result[:limit]

    def clear(self) -> None:
        """Clear stored alerts."""
        with self._lock:
            self.path.write_text("", encoding="utf-8")

    def count(self) -> int:
        """Return the number of unique alerts in the store."""
        return len(self.recent(limit=1_000_000))

    def _existing_keys(self) -> set[str]:
        if not self.path.exists():
            return set()

        keys: set[str] = set()
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = self._dedupe_key(record)
                if key:
                    keys.add(key)
        return keys

    def _dedupe_key(self, alert: Dict[str, Any]) -> Optional[str]:
        metadata = alert.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("dedupe_key"):
            return str(metadata["dedupe_key"])

        event = alert.get("event", {})
        if isinstance(event, dict):
            event_hash = event.get("hash_id")
            if event_hash:
                return f"{event_hash}:{alert.get('threat_level', '')}"
            hash_seed = f"{event.get('event_type', '')}_{event.get('timestamp', '')}"
            if event.get("source_ip"):
                hash_seed += f"_{event['source_ip']}"
            if event.get("destination_ip"):
                hash_seed += f"_{event['destination_ip']}"
            if event.get("username"):
                hash_seed += f"_{event['username']}"
            if hash_seed != "_":
                return f"{hashlib.md5(hash_seed.encode()).hexdigest()}:{alert.get('threat_level', '')}"

        return None
