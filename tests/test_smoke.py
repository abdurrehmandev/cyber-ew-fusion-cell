from datetime import datetime, timezone

from core.attack_timeline import build_attack_timeline
from core.collectors.manager import collector_readiness
from core.collectors.win_eventlog import event_xml_to_raw
from core.engines.normalization_engine import NormalizationEngine
from core.engines.ingest_engine import IngestEngine
from core.engines.ml_anomaly_engine import MLAnomalyEngine
from core.engines.scoring_engine import ScoringEngine
from core.engines.signature_engine import SignatureEngine
from core.models.event_models import EventSeverity, EventType, NormalizedEvent
from core.sensor_parsers import normalize_sensor_record, parse_sensor_file
from config.deployment import get_profile, profile_names
from storage.alert_store import AlertStore
from storage.soc_store import AuditLog, CaseStore, IOCStore


def test_normalization_preserves_behavior_fields():
    engine = NormalizationEngine()
    event = engine.normalize(
        {
            "timestamp": "2026-06-01T00:00:00Z",
            "event_type": "file_access",
            "source_ip": "192.168.1.55",
            "file_path": "C:/Users/Public/report.docx.crypt",
            "severity": "critical",
            "details": {"operation": "encrypt", "message": "bulk file rename detected"},
        },
        "json",
    )

    assert event is not None
    assert event.event_type == EventType.FILE_ACCESS
    assert event.file_path.endswith(".crypt")
    assert event.details["operation"] == "encrypt"
    assert event.timestamp.tzinfo == timezone.utc


def test_ingest_preserves_live_detection_fields():
    engine = IngestEngine()
    event = engine._normalize_event(
        {
            "timestamp": "2026-06-01T00:00:00Z",
            "event_type": "process_creation",
            "source_ip": "192.168.1.55",
            "process_name": "7z.exe",
            "file_path": "C:/Temp/archive.7z",
            "severity": "high",
            "confidence": 0.8,
            "details": {"command": "7z.exe a C:/Temp/archive.7z C:/Sensitive/*"},
        },
        "json",
    )

    assert event is not None
    assert event.process_name == "7z.exe"
    assert event.file_path.endswith("archive.7z")
    assert event.severity == EventSeverity.HIGH
    assert event.confidence == 0.8


def test_sensor_parsers_normalize_suricata_and_zeek(tmp_path):
    suricata = normalize_sensor_record(
        {
            "timestamp": "2026-06-01T00:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "src_port": 51510,
            "dest_ip": "203.0.113.50",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {"signature": "ET MALWARE Possible C2 Beacon", "category": "Malware", "severity": 1},
        }
    )
    assert suricata["source_type"] == "suricata"
    assert suricata["event_type"] == "network_connection"
    assert suricata["severity"] == "critical"
    assert suricata["details"]["signature"].startswith("ET MALWARE")

    zeek_file = tmp_path / "conn.log"
    zeek_file.write_text(
        "#separator \\x09\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\n"
        "1770000000.0\tC1\t10.0.0.5\t51510\t203.0.113.50\t443\ttcp\tssl\t900\t4200\n",
        encoding="utf-8",
    )
    zeek = parse_sensor_file(zeek_file)[0]
    assert zeek["source_type"] == "zeek"
    assert zeek["source_ip"] == "10.0.0.5"
    assert zeek["destination_port"] == 443


def test_sensor_parser_normalizes_windows_sysmon():
    event = normalize_sensor_record(
        {
            "EventID": 1,
            "EventTime": "2026-06-01T00:00:00Z",
            "Computer": "workstation-7",
            "User": "alice",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand AAAA",
        }
    )

    assert event["source_type"] == "windows_event"
    assert event["event_type"] == "process_creation"
    assert event["source_host"] == "workstation-7"
    assert event["severity"] == "medium"


def test_attack_timeline_maps_mitre_techniques():
    timeline = build_attack_timeline(
        [
            {
                "timestamp": "2026-06-01T00:00:00Z",
                "patterns": "Credential stuffing",
                "source_ip": "10.0.0.5",
                "event_type": "authentication",
            },
            {
                "timestamp": "2026-06-01T00:05:00Z",
                "patterns": "Ransomware activity",
                "file_path": "C:/Users/Public/report.docx.locked",
                "event_type": "file_access",
            },
        ]
    )

    assert [item["technique_id"] for item in timeline] == ["T1110", "T1486"]


def test_deployment_profiles_are_available():
    names = profile_names()
    assert {"dev", "demo", "offline", "production"}.issubset(set(names))
    production = get_profile("production")
    assert production.api_key_required is True
    assert production.dashboard_url.startswith("http://127.0.0.1:")


def test_windows_event_xml_maps_to_raw_record():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Sysmon"/>
        <EventID>1</EventID>
        <TimeCreated SystemTime="2026-06-01T00:00:00.0000000Z"/>
        <EventRecordID>42</EventRecordID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>host-1</Computer>
      </System>
      <EventData>
        <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -EncodedCommand AAAA</Data>
      </EventData>
    </Event>"""
    record = event_xml_to_raw(xml)

    assert record["EventID"] == 1
    assert record["Computer"] == "host-1"
    assert record["Image"].endswith("powershell.exe")
    assert record["_record_id"] == 42


def test_collector_readiness_probe_is_safe():
    status = collector_readiness()
    assert {"windows_eventlog", "sysmon", "pcap_live"}.issubset(status)


def test_behavior_pattern_scoring_uses_severity_and_confidence():
    class Pattern:
        confidence = 0.9
        severity = EventSeverity.CRITICAL

    score = ScoringEngine()._calculate_behavior_score([Pattern()])
    assert score >= 0.9


def test_ml_unfitted_models_fall_back_to_heuristics():
    engine = MLAnomalyEngine()
    engine.models_trained = True

    result = engine.detect_anomalies(
        NormalizedEvent(
            event_id="evt-ml-fallback",
            event_type=EventType.NETWORK_CONNECTION,
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
            destination_ip="203.0.113.10",
            port=65000,
            protocol="TCP",
            severity=EventSeverity.HIGH,
        )
    )

    assert "heuristic" in result["scores"]
    assert engine.models_trained is False


def test_alert_store_deduplicates_by_event_hash(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    event = NormalizedEvent(
        event_id="evt-1",
        event_type=EventType.FILE_ACCESS,
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        source_ip="192.168.1.55",
        severity=EventSeverity.CRITICAL,
    )
    alert = {
        "alert_id": "alert-1",
        "event": event.to_dict(),
        "threat_level": "high",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    assert store.append(alert) is True
    assert store.append({**alert, "alert_id": "alert-2"}) is False
    assert store.count() == 1


def test_case_and_ioc_stores_are_persistent(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    cases = CaseStore(tmp_path / "cases.json", audit)
    iocs = IOCStore(tmp_path / "iocs.json", audit)

    case = cases.upsert_for_alert(
        "alert-1",
        {"level": "High", "score": 0.8, "source_ip": "10.0.0.5", "patterns": "C2 Beaconing"},
        status="Investigating",
        owner="analyst",
        tags=["c2"],
    )
    ioc = iocs.add("10.0.0.5", "ip", threat_type="c2", confidence=0.8)

    assert case["case_id"].startswith("CASE-")
    assert cases.summary()["open_cases"] == 1
    assert ioc["value"] == "10.0.0.5"
    assert iocs.match_event({"source_ip": "10.0.0.5"})
    assert audit.recent(limit=10)


def test_api_imports():
    from interfaces.api import app

    assert app.title == "Cyber-EW Fusion Cell API"


def test_yara_rules_without_payload_do_not_error():
    engine = SignatureEngine()
    event = NormalizedEvent(
        event_id="evt-yara-empty",
        event_type=EventType.NETWORK_CONNECTION,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.10",
        details={"message": "ordinary network event"},
    )

    assert isinstance(engine.scan_event(event), list)
