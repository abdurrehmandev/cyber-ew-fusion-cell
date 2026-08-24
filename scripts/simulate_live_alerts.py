#!/usr/bin/env python3
"""
Write pipeline-shaped alerts into the durable alert store.

This is useful for dashboard demos before real sensors are connected.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.engines.output_engine import OutputEngine
from core.engines.scoring_engine import ThreatLevel, ThreatScore
from core.models.event_models import EventSeverity, EventType, NormalizedEvent


def build_event(index: int) -> tuple[NormalizedEvent, ThreatScore]:
    now = datetime.now(timezone.utc) - timedelta(seconds=index * 20)

    scenarios = [
        (
            NormalizedEvent(
                event_id=f"live_ransomware_{index}",
                event_type=EventType.FILE_ACCESS,
                timestamp=now,
                source_ip="192.168.1.55",
                file_path=f"C:/Users/Public/file_{index}.docx.locked",
                severity=EventSeverity.CRITICAL,
                details={"operation": "encrypt", "message": "bulk encryption behavior"},
            ),
            ThreatScore(0.95, ThreatLevel.CRITICAL, 0.9, ["behavior"], {"scenario": "ransomware"}),
        ),
        (
            NormalizedEvent(
                event_id=f"live_c2_{index}",
                event_type=EventType.NETWORK_CONNECTION,
                timestamp=now,
                source_ip="192.168.1.42",
                destination_ip="203.0.113.50",
                port=443,
                protocol="TCP",
                bytes_sent=900,
                bytes_received=4200,
                severity=EventSeverity.HIGH,
                details={"interval": "periodic", "repeat_count": 6, "message": "beacon-like callback"},
            ),
            ThreatScore(0.86, ThreatLevel.CRITICAL, 0.82, ["behavior", "signature"], {"scenario": "c2_beacon"}),
        ),
        (
            NormalizedEvent(
                event_id=f"live_smb_{index}",
                event_type=EventType.NETWORK_CONNECTION,
                timestamp=now,
                source_ip="192.168.1.66",
                destination_ip="192.168.10.20",
                port=445,
                protocol="TCP",
                severity=EventSeverity.HIGH,
                details={"success": False, "message": "SMB lateral movement attempt"},
            ),
            ThreatScore(0.78, ThreatLevel.HIGH, 0.76, ["behavior"], {"scenario": "lateral_movement"}),
        ),
    ]

    return scenarios[index % len(scenarios)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate live Cyber-EW alerts")
    parser.add_argument("--count", type=int, default=6)
    parser.add_argument("--clear", action="store_true", help="Clear existing stored alerts first")
    args = parser.parse_args()

    output = OutputEngine()
    if args.clear:
        output.alert_store.clear()

    for index in range(args.count):
        event, score = build_event(index)
        output.publish_alert(event, score, correlation_result=None, behavior_result=None)

    print(f"Wrote {args.count} alerts to {output.alert_store.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
