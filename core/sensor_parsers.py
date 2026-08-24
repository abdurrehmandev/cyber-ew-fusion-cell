"""
Production sensor parsers for common SOC telemetry formats.

The functions in this module convert real-world sensor records into the
project's common raw-event shape before the normalization engine runs.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


ZEEK_SUFFIXES = {".log", ".tsv"}
JSONL_SUFFIXES = {".jsonl", ".ndjson", ".eve"}


def parse_sensor_file(path: Path) -> List[Dict[str, Any]]:
    """Parse a supported sensor file into raw event dictionaries."""
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".json":
        parsed = json.loads(path.read_text(encoding="utf-8"))
        return [normalize_sensor_record(record) for record in extract_json_records(parsed)]

    if suffix in JSONL_SUFFIXES:
        records: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                records.append(normalize_sensor_record(parsed))
        return records

    if suffix in ZEEK_SUFFIXES:
        return [normalize_sensor_record(record) for record in parse_zeek_tsv(path)]

    return []


def extract_json_records(parsed: Any) -> List[Dict[str, Any]]:
    """Extract event dictionaries from common JSON container shapes."""
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]

    if isinstance(parsed, dict):
        for key in ("events", "alerts", "records", "data"):
            value = parsed.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [parsed]

    return []


def normalize_sensor_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-detect and normalize a single sensor record."""
    if is_suricata(record):
        return normalize_suricata(record)
    if is_zeek(record):
        return normalize_zeek(record)
    if is_windows_event(record):
        return normalize_windows_event(record)

    normalized = dict(record)
    normalized.setdefault("source_type", "json")
    return normalized


def is_suricata(record: Dict[str, Any]) -> bool:
    return bool({"src_ip", "dest_ip"} <= set(record) and ("event_type" in record or "alert" in record))


def is_zeek(record: Dict[str, Any]) -> bool:
    return "id.orig_h" in record or "id.resp_h" in record or record.get("_path") in {"conn", "dns", "http", "ssl", "notice"}


def is_windows_event(record: Dict[str, Any]) -> bool:
    return any(key in record for key in ("EventID", "EventId", "event_id", "winlog", "EventData")) or "winlog.event_id" in record


def normalize_suricata(record: Dict[str, Any]) -> Dict[str, Any]:
    alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
    dns = record.get("dns") if isinstance(record.get("dns"), dict) else {}
    http = record.get("http") if isinstance(record.get("http"), dict) else {}
    event_type = str(record.get("event_type", "")).lower()

    severity = suricata_severity(alert.get("severity"))
    mapped_type = {
        "dns": "dns_query",
        "http": "http_request",
        "alert": "network_connection",
        "flow": "network_connection",
        "tls": "network_connection",
    }.get(event_type, "network_connection")

    details = {
        "sensor": "suricata",
        "sensor_event_type": event_type,
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category"),
        "action": alert.get("action"),
        "flow_id": record.get("flow_id"),
        "app_proto": record.get("app_proto"),
        "dns_query": dns.get("rrname"),
        "http_hostname": http.get("hostname"),
        "http_url": http.get("url"),
        "raw": record,
    }

    return compact(
        {
            "timestamp": record.get("timestamp"),
            "source_ip": record.get("src_ip"),
            "source_port": record.get("src_port"),
            "destination_ip": record.get("dest_ip"),
            "destination_port": record.get("dest_port"),
            "protocol": record.get("proto"),
            "event_type": mapped_type,
            "severity": severity,
            "url": http.get("url"),
            "details": details,
            "source_type": "suricata",
            "source_name": "suricata_eve",
        }
    )


def suricata_severity(value: Any) -> str:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return "medium"
    if numeric <= 1:
        return "critical"
    if numeric == 2:
        return "high"
    if numeric == 3:
        return "medium"
    return "low"


def normalize_zeek(record: Dict[str, Any]) -> Dict[str, Any]:
    path = str(record.get("_path") or record.get("path") or "").lower()
    if not path:
        if "query" in record:
            path = "dns"
        elif "host" in record or "uri" in record:
            path = "http"
        else:
            path = "conn"

    event_type = {
        "dns": "dns_query",
        "http": "http_request",
        "conn": "network_connection",
        "ssl": "network_connection",
        "notice": "system_alert",
    }.get(path, "network_connection")

    details = {
        "sensor": "zeek",
        "log_type": path,
        "uid": record.get("uid"),
        "service": record.get("service"),
        "duration": record.get("duration"),
        "conn_state": record.get("conn_state"),
        "query": record.get("query"),
        "method": record.get("method"),
        "host": record.get("host"),
        "uri": record.get("uri"),
        "notice": record.get("note"),
        "message": record.get("msg"),
        "raw": record,
    }

    return compact(
        {
            "timestamp": normalize_zeek_timestamp(record.get("ts")),
            "source_ip": record.get("id.orig_h"),
            "source_port": record.get("id.orig_p"),
            "destination_ip": record.get("id.resp_h"),
            "destination_port": record.get("id.resp_p"),
            "protocol": record.get("proto"),
            "event_type": event_type,
            "bytes_sent": record.get("orig_bytes"),
            "bytes_received": record.get("resp_bytes"),
            "url": build_http_url(record),
            "severity": "medium" if path == "notice" else "info",
            "details": details,
            "source_type": "zeek",
            "source_name": f"zeek_{path}",
        }
    )


def normalize_zeek_timestamp(value: Any) -> Any:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return value


def build_http_url(record: Dict[str, Any]) -> str:
    host = record.get("host")
    uri = record.get("uri")
    if host and uri:
        return f"http://{host}{uri}"
    return ""


def normalize_windows_event(record: Dict[str, Any]) -> Dict[str, Any]:
    data = flatten_windows_event(record)
    event_id = str(data.get("EventID") or data.get("EventId") or data.get("event_id") or data.get("event.code") or "")

    event_type = windows_event_type(event_id, data)
    severity = windows_event_severity(event_id, data)
    details = {
        "sensor": "windows_event",
        "event_id": event_id,
        "channel": data.get("Channel") or data.get("winlog.channel"),
        "message": data.get("Message") or data.get("message"),
        "command": data.get("CommandLine") or data.get("ProcessCommandLine") or data.get("process.command_line"),
        "parent_process": data.get("ParentProcessName") or data.get("process.parent.executable"),
        "logon_type": data.get("LogonType"),
        "success": event_id not in {"4625", "4771"},
        "raw": record,
    }

    return compact(
        {
            "timestamp": data.get("EventTime") or data.get("TimeCreated") or data.get("@timestamp") or data.get("timestamp"),
            "source_ip": data.get("IpAddress") or data.get("SourceIp") or data.get("SourceAddress") or data.get("source.ip"),
            "source_host": data.get("Computer") or data.get("Hostname") or data.get("host.name"),
            "destination_ip": data.get("DestinationIp") or data.get("dest.ip") or data.get("destination.ip"),
            "destination_port": data.get("DestinationPort") or data.get("dest.port") or data.get("destination.port"),
            "username": data.get("TargetUserName") or data.get("User") or data.get("UserName") or data.get("user.name"),
            "process_name": data.get("NewProcessName") or data.get("Image") or data.get("ProcessName") or data.get("process.executable"),
            "file_path": data.get("TargetFilename") or data.get("ObjectName") or data.get("file.path"),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "source_type": "windows_event",
            "source_name": f"windows_{event_id or 'event'}",
        }
    )


def flatten_windows_event(record: Dict[str, Any]) -> Dict[str, Any]:
    flat = dict(record)
    winlog = record.get("winlog")
    if isinstance(winlog, dict):
        flat["winlog.event_id"] = winlog.get("event_id")
        flat["winlog.channel"] = winlog.get("channel")
        event_data = winlog.get("event_data")
        if isinstance(event_data, dict):
            flat.update(event_data)

    event_data = record.get("EventData")
    if isinstance(event_data, dict):
        flat.update(event_data)

    process = record.get("process")
    if isinstance(process, dict):
        flat["process.executable"] = process.get("executable")
        flat["process.command_line"] = process.get("command_line")
        parent = process.get("parent")
        if isinstance(parent, dict):
            flat["process.parent.executable"] = parent.get("executable")

    host = record.get("host")
    if isinstance(host, dict):
        flat["host.name"] = host.get("name")

    user = record.get("user")
    if isinstance(user, dict):
        flat["user.name"] = user.get("name")

    event = record.get("event")
    if isinstance(event, dict):
        flat["event.code"] = event.get("code")

    source = record.get("source")
    if isinstance(source, dict):
        flat["source.ip"] = source.get("ip")

    destination = record.get("destination")
    if isinstance(destination, dict):
        flat["destination.ip"] = destination.get("ip")
        flat["destination.port"] = destination.get("port")

    file_info = record.get("file")
    if isinstance(file_info, dict):
        flat["file.path"] = file_info.get("path")

    return flat


def windows_event_type(event_id: str, data: Dict[str, Any]) -> str:
    if event_id in {"4624", "4625", "4771", "4776"}:
        return "authentication"
    if event_id == "1" or data.get("NewProcessName") or data.get("Image") or data.get("process.executable"):
        return "process_creation"
    if event_id == "3" or data.get("DestinationIp"):
        return "network_connection"
    if event_id in {"11", "4663"} or data.get("TargetFilename"):
        return "file_access"
    if event_id in {"12", "13", "14"}:
        return "registry_modification"
    if event_id in {"4698", "4702"}:
        return "scheduled_task"
    if event_id == "22" or data.get("QueryName"):
        return "dns_query"
    return "system_alert"


def windows_event_severity(event_id: str, data: Dict[str, Any]) -> str:
    command = " ".join(
        str(data.get(key, ""))
        for key in ("CommandLine", "ProcessCommandLine", "process.command_line", "NewProcessName", "Image")
    ).lower()
    if event_id in {"4625", "4771", "4698", "4702"}:
        return "high"
    if any(token in command for token in ("powershell", "schtasks", "rundll32", "regsvr32", "encodedcommand")):
        return "medium"
    return "info"


def parse_zeek_tsv(path: Path) -> List[Dict[str, Any]]:
    """Parse Zeek TSV logs that include #fields headers."""
    records: List[Dict[str, Any]] = []
    fields: List[str] = []
    log_type = path.stem.split(".")[0]

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line:
            continue
        if line.startswith("#path"):
            parts = line.split("\t")
            if len(parts) > 1:
                log_type = parts[1]
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue

        values = line.split("\t")
        record = {field: clean_zeek_value(value) for field, value in zip(fields, values)}
        record["_path"] = log_type
        records.append(record)

    return records


def clean_zeek_value(value: str) -> Any:
    if value in {"-", "(empty)"}:
        return ""
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def compact(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Drop empty values, while preserving booleans and zeros."""
    return {key: value for key, value in payload.items() if value not in (None, "")}
