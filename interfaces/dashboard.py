#!/usr/bin/env python3
"""
Cyber-EW Fusion Cell analyst dashboard.
"""
from __future__ import annotations

import json
import hashlib
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.attack_timeline import build_attack_timeline, build_investigation_report
from core.capability_center import capability_matrix, connector_readiness, installer_action_plan, runtime_mode_summary
from core.connectors.catalog import connector_catalog, connector_summary
from core.soar_engine import PlaybookEngine
from config.settings import CONFIG
from scripts.generate_sample_data import generate_events, write_syslog
from storage import AuditLog, CaseStore, HuntingQueryEngine, IOCStore, SecurityLake


DATA_DIR = CONFIG.data_dir
SAMPLE_DIR = DATA_DIR / "inputs" / "sample_generated"
DEFAULT_EVENTS = SAMPLE_DIR / "sample_events.json"
PIPELINE_STATS = DATA_DIR / "pipeline_stats.json"
BEHAVIOR_PROFILES = DATA_DIR / "behavior_profiles.json"
DASHBOARD_STATE = DATA_DIR / "outputs" / "dashboard_state.json"
ALERTS_JSONL = DATA_DIR / "outputs" / "alerts.jsonl"
SERVICE_STATUS = DATA_DIR / "outputs" / "service_status.json"
IMPORTED_DIR = DATA_DIR / "inputs" / "imported"
ALERT_STATUSES = ["New", "Investigating", "Contained", "False Positive", "Closed"]
CASE_DISPOSITIONS = ["Undetermined", "True Positive", "False Positive", "Benign", "Duplicate"]
PLAYBOOKS = {
    "Ransomware": [
        "Isolate affected host from network",
        "Collect process tree, scheduled tasks, and recent file changes",
        "Disable compromised accounts and rotate exposed credentials",
        "Preserve encrypted file samples and ransom notes",
    ],
    "C2 Beaconing": [
        "Block destination at DNS, proxy, and firewall controls",
        "Collect endpoint network timeline and parent process",
        "Search for same destination across all entities",
        "Acquire memory or EDR triage package if beaconing persists",
    ],
    "Credential Attack": [
        "Lock or reset targeted accounts",
        "Review source host ownership and successful logons",
        "Check MFA fatigue, impossible travel, and password spray indicators",
        "Add attacking source to watchlist if malicious",
    ],
    "Data Exfiltration": [
        "Block destination and inspect proxy/firewall transfer logs",
        "Identify files accessed before outbound transfer",
        "Review DLP, cloud storage, and archive creation evidence",
        "Escalate to incident response lead for impact assessment",
    ],
    "General Investigation": [
        "Validate alert against raw telemetry",
        "Pivot on source, destination, user, process, and file path",
        "Document evidence and containment decision",
        "Close with disposition and follow-up actions",
    ],
}

audit_log = AuditLog(DATA_DIR / "outputs" / "audit_log.jsonl")
case_store = CaseStore(DATA_DIR / "outputs" / "cases.json", audit_log)
ioc_store = IOCStore(DATA_DIR / "threat_intel" / "local_iocs.json", audit_log)
security_lake = SecurityLake(DATA_DIR)
hunting_engine = HuntingQueryEngine(security_lake)
playbook_engine = PlaybookEngine(audit_log)


st.set_page_config(
    page_title="Cyber-EW Fusion Cell",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed",
)


st.markdown(
    """
    <style>
    :root {
        --bg: #0b0f14;
        --panel: #111821;
        --panel-2: #151e29;
        --line: #243244;
        --text: #e8edf2;
        --muted: #94a3b8;
        --green: #35d07f;
        --amber: #f2b84b;
        --red: #ff5c70;
        --cyan: #46c7ff;
    }
    .stApp {
        background:
            linear-gradient(180deg, rgba(19, 27, 36, .98), rgba(8, 12, 17, 1) 460px),
            #0b0f14;
        color: var(--text);
    }
    [data-testid="stSidebar"] {
        background: #0e151d;
        border-right: 1px solid var(--line);
    }
    .block-container {
        padding-top: 1.35rem;
        padding-bottom: 2.5rem;
        max-width: 1480px;
    }
    h1, h2, h3 {
        letter-spacing: 0;
    }
    .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 14px 16px 16px;
        border: 1px solid var(--line);
        background: rgba(17, 24, 33, .92);
        border-radius: 8px;
        margin-bottom: 16px;
    }
    .brand-title {
        font-size: 1.55rem;
        font-weight: 780;
        line-height: 1.12;
        margin: 0;
    }
    .brand-subtitle {
        color: var(--muted);
        margin-top: 4px;
        font-size: .92rem;
    }
    .status-pill {
        border: 1px solid rgba(53, 208, 127, .45);
        color: var(--green);
        background: rgba(53, 208, 127, .1);
        padding: 7px 10px;
        border-radius: 999px;
        font-weight: 700;
        white-space: nowrap;
        font-size: .85rem;
    }
    .metric-card {
        border: 1px solid var(--line);
        background: rgba(17, 24, 33, .92);
        border-radius: 8px;
        padding: 14px 14px 12px;
        min-height: 98px;
    }
    .metric-label {
        color: var(--muted);
        font-size: .82rem;
        margin-bottom: 8px;
    }
    .metric-value {
        font-size: 1.85rem;
        font-weight: 800;
        line-height: 1;
    }
    .metric-foot {
        color: var(--muted);
        font-size: .78rem;
        margin-top: 10px;
    }
    .section-shell {
        border: 1px solid var(--line);
        background: rgba(17, 24, 33, .76);
        border-radius: 8px;
        padding: 13px 14px 8px;
        margin-bottom: 14px;
    }
    .section-title {
        font-size: 1.02rem;
        font-weight: 760;
        margin-bottom: 10px;
    }
    div[data-testid="stMetric"] {
        background: rgba(17, 24, 33, .92);
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 10px 12px;
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 8px;
        overflow: hidden;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
    }
    .stTabs [data-baseweb="tab"] {
        border: 1px solid var(--line);
        border-radius: 8px;
        background: #111821;
        padding: 8px 12px;
    }
    .stTabs [aria-selected="true"] {
        border-color: var(--cyan);
        color: var(--cyan);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_json(path: Path, fallback: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    return fallback


def load_dashboard_state() -> Dict[str, Any]:
    state = read_json(DASHBOARD_STATE, {"alerts": {}})
    if not isinstance(state, dict):
        state = {"alerts": {}}
    state.setdefault("alerts", {})
    return state


def save_dashboard_state(state: Dict[str, Any]) -> None:
    DASHBOARD_STATE.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD_STATE.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def service_health() -> Tuple[str, str]:
    status = read_json(SERVICE_STATUS, {})
    updated_at = status.get("updated_at") if isinstance(status, dict) else None
    if not updated_at:
        return "Dashboard Only", "No live service heartbeat"

    try:
        timestamp = pd.to_datetime(updated_at, utc=True)
        age_seconds = (pd.Timestamp.now(tz="UTC") - timestamp).total_seconds()
    except Exception:
        return "Unknown", "Heartbeat timestamp unreadable"

    if status.get("status") == "running" and age_seconds <= 10:
        pipeline = status.get("pipeline", {})
        processed = pipeline.get("events_processed", 0) if isinstance(pipeline, dict) else 0
        return "Live", f"Heartbeat {age_seconds:.0f}s ago | {processed:,} events"
    if status.get("status") == "stopped":
        return "Stopped", "Live service stopped"
    return "Stale", f"Last heartbeat {age_seconds:.0f}s ago"


def live_pipeline_stats() -> Dict[str, Any]:
    status = read_json(SERVICE_STATUS, {})
    if isinstance(status, dict) and isinstance(status.get("pipeline"), dict):
        return status["pipeline"]
    stats = read_json(PIPELINE_STATS, {})
    return stats if isinstance(stats, dict) else {}


def service_snapshot() -> Dict[str, Any]:
    status = read_json(SERVICE_STATUS, {})
    return status if isinstance(status, dict) else {}


def update_alert_state(alert_id: str, status: str | None = None, notes: str | None = None) -> None:
    state = st.session_state.dashboard_state
    alert_state = state.setdefault("alerts", {}).setdefault(alert_id, {})
    if status is not None:
        alert_state["status"] = status
    if notes is not None:
        alert_state["notes"] = notes
    alert_state["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_dashboard_state(state)


def infer_playbook(patterns: str) -> str:
    lowered = patterns.lower()
    if "ransomware" in lowered:
        return "Ransomware"
    if "beacon" in lowered or "c2" in lowered:
        return "C2 Beaconing"
    if "credential" in lowered or "authentication" in lowered:
        return "Credential Attack"
    if "exfil" in lowered or "staging" in lowered:
        return "Data Exfiltration"
    return "General Investigation"


def load_cases() -> pd.DataFrame:
    cases = case_store.all()
    return pd.DataFrame(cases)


def load_iocs() -> pd.DataFrame:
    iocs = ioc_store.all()
    return pd.DataFrame(iocs)


def clean_for_json(value: Any) -> Any:
    if isinstance(value, float) and pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: clean_for_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean_for_json(item) for item in value]
    return value


def discover_event_files() -> List[Path]:
    files = sorted((DATA_DIR / "inputs").rglob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if ALERTS_JSONL.exists() and ALERTS_JSONL.stat().st_size > 0:
        files.insert(0, ALERTS_JSONL)
    if DEFAULT_EVENTS not in files and DEFAULT_EVENTS.exists():
        files.insert(0, DEFAULT_EVENTS)
    return files


def display_path(path: Path | None) -> str:
    if path is None:
        return ""
    for base in (DATA_DIR, PROJECT_ROOT):
        try:
            return str(path.relative_to(base))
        except ValueError:
            continue
    return str(path)


def save_uploaded_telemetry(uploaded_file: Any) -> Path:
    IMPORTED_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(uploaded_file.name).name
    target = IMPORTED_DIR / safe_name
    target.write_bytes(uploaded_file.getvalue())
    return target


def alert_dedupe_key(alert: Dict[str, Any]) -> str:
    metadata = alert.get("metadata", {})
    if isinstance(metadata, dict) and metadata.get("dedupe_key"):
        return str(metadata["dedupe_key"])

    event = alert.get("event", {})
    if isinstance(event, dict) and event.get("hash_id"):
        return f"{event['hash_id']}:{alert.get('threat_level', '')}"
    if isinstance(event, dict):
        hash_seed = f"{event.get('event_type', '')}_{event.get('timestamp', '')}"
        if event.get("source_ip"):
            hash_seed += f"_{event['source_ip']}"
        if event.get("destination_ip"):
            hash_seed += f"_{event['destination_ip']}"
        if event.get("username"):
            hash_seed += f"_{event['username']}"
        if hash_seed != "_":
            return f"{hashlib.md5(hash_seed.encode()).hexdigest()}:{alert.get('threat_level', '')}"

    return str(alert.get("alert_id", ""))


def read_records(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        deduped: Dict[str, Dict[str, Any]] = {}
        for record in records:
            key = alert_dedupe_key(record) if isinstance(record, dict) and "alert_id" in record else ""
            if not key or key not in deduped:
                deduped[key or str(len(deduped))] = record
        return list(deduped.values())

    raw = read_json(path, [])
    if isinstance(raw, dict):
        raw = raw.get("events", raw.get("alerts", []))
    return raw if isinstance(raw, list) else []


def normalize_event_record(event: Dict[str, Any]) -> Dict[str, Any]:
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    port = event.get("port") or event.get("destination_port") or details.get("destination_port")
    bytes_sent = event.get("bytes_sent") or details.get("bytes_sent") or 0
    bytes_received = event.get("bytes_received") or details.get("bytes_received") or 0
    timestamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat()

    return {
        "timestamp": timestamp,
        "event_type": event.get("event_type", "system_alert"),
        "source_ip": event.get("source_ip") or event.get("src_ip") or "",
        "destination_ip": event.get("destination_ip") or event.get("dest_ip") or "",
        "username": event.get("username") or details.get("username") or "",
        "port": int(port) if str(port).isdigit() else None,
        "protocol": event.get("protocol") or details.get("protocol") or "",
        "severity": str(event.get("severity", "info")).lower(),
        "bytes_sent": int(bytes_sent or 0),
        "bytes_received": int(bytes_received or 0),
        "process_name": event.get("process_name") or "",
        "file_path": event.get("file_path") or details.get("file_path") or "",
        "details": details,
    }


def is_external_ip(ip: str) -> bool:
    return bool(ip) and not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127."))


def score_event(event: Dict[str, Any]) -> Tuple[float, str, List[str]]:
    details = event["details"]
    severity_score = {
        "critical": 0.92,
        "high": 0.74,
        "medium": 0.52,
        "low": 0.26,
        "info": 0.12,
    }.get(event["severity"], 0.16)

    score = severity_score
    patterns: List[str] = []
    event_type = event["event_type"]
    message = str(details.get("message", "")).lower()
    command = " ".join([event["process_name"], str(details.get("command", "")), str(details.get("process_command_line", ""))]).lower()
    file_path = event["file_path"].lower()

    if event_type == "authentication" and details.get("success") is False:
        score = max(score, 0.78)
        patterns.append("Credential attack")
        if int(details.get("attempts", 1) or 1) > 8:
            score = max(score, 0.9)
            patterns.append("Credential stuffing")

    if event_type == "network_connection" and event["port"] in {445, 139, 3389, 22}:
        score = max(score, 0.68)
        patterns.append("Lateral movement")

    if event_type == "network_connection" and is_external_ip(event["destination_ip"]) and event["bytes_sent"] > 1_000_000:
        score = max(score, 0.86)
        patterns.append("Data exfiltration")

    if event_type == "network_connection" and is_external_ip(event["destination_ip"]) and details.get("interval") in {"periodic", "regular", "beacon"}:
        score = max(score, 0.82)
        patterns.append("C2 beaconing")

    if event_type == "file_access" and any(token in file_path or token in message for token in [".encrypted", ".locked", ".crypt", "encrypt"]):
        score = max(score, 0.95)
        patterns.append("Ransomware activity")

    if event_type in {"process_creation", "file_access"} and any(token in command or token in file_path for token in [".zip", ".rar", ".7z", ".tar", "archive", "compress", "7z.exe"]):
        score = max(score, 0.64)
        patterns.append("Data staging")

    if event_type in {"scheduled_task", "process_creation"} and any(token in command for token in ["schtasks", "runas", "uac", "token"]):
        score = max(score, 0.78)
        patterns.append("Privilege escalation")

    if not patterns and event["severity"] in {"high", "critical"}:
        patterns.append("High severity telemetry")

    if score >= 0.85:
        level = "Critical"
    elif score >= 0.7:
        level = "High"
    elif score >= 0.5:
        level = "Medium"
    elif score >= 0.3:
        level = "Low"
    else:
        level = "Info"

    return round(min(score, 1.0), 2), level, patterns


def live_alert_patterns(alert: Dict[str, Any]) -> List[str]:
    """Build concise dashboard labels for persisted pipeline alerts."""
    scenario_map = {
        "ransomware": "Ransomware activity",
        "c2_beacon": "C2 beaconing",
        "lateral_movement": "Lateral movement",
        "data_exfiltration": "Data exfiltration",
        "credential_attack": "Credential attack",
    }

    details = alert.get("threat_score", {}).get("details", {})
    scenario = details.get("scenario")
    if scenario in scenario_map:
        return [scenario_map[scenario]]

    behavior_patterns = alert.get("behavior_analysis", {}).get("patterns", [])
    labels = [
        pattern.get("description") or pattern.get("pattern_type", "")
        for pattern in behavior_patterns
        if isinstance(pattern, dict)
    ]
    if labels:
        return labels

    sources = alert.get("threat_score", {}).get("sources", [])
    if sources:
        return [", ".join(str(source).replace("_", " ").title() for source in sources)]

    return ["Pipeline alert"]


def load_events(path: Path) -> pd.DataFrame:
    raw = read_records(path)
    records = []
    for index, event in enumerate(raw if isinstance(raw, list) else []):
        is_alert = isinstance(event, dict) and "alert_id" in event and "event" in event
        source_event = event.get("event", {}) if is_alert else event
        normalized = normalize_event_record(source_event)

        if is_alert:
            threat_score = event.get("threat_score", {})
            score = round(float(threat_score.get("score", 0.0) or 0.0), 2)
            level = str(threat_score.get("level", "info")).title()
            patterns = live_alert_patterns(event)
        else:
            score, level, patterns = score_event(normalized)

        normalized.update(
            {
                "event_id": event.get("alert_id") if is_alert else event.get("event_id") or f"evt-{index + 1:05d}",
                "score": score,
                "level": level,
                "patterns": ", ".join(patterns) if patterns else "Routine",
                "total_bytes": normalized["bytes_sent"] + normalized["bytes_received"],
                "record_source": "live_alert" if is_alert else "telemetry",
            }
        )
        records.append(normalized)

    df = pd.DataFrame(records)
    if not df.empty:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values("timestamp_dt", ascending=False)
    return df


def load_profiles() -> pd.DataFrame:
    profiles = read_json(BEHAVIOR_PROFILES, {})
    records = []
    for profile in profiles.values() if isinstance(profiles, dict) else []:
        event_total = sum(item.get("count", 0) for item in profile.get("event_frequencies", {}).values())
        records.append(
            {
                "entity_type": profile.get("entity_type", ""),
                "entity_id": profile.get("entity_id", ""),
                "status": profile.get("baseline_status", ""),
                "events": event_total,
                "destinations": len(profile.get("common_destinations", {})),
                "ports": len(profile.get("common_ports", {})),
                "period_end": profile.get("period_end", ""),
            }
        )
    return pd.DataFrame(records)


def metric_card(label: str, value: Any, foot: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state() -> None:
    st.markdown('<div class="section-shell"><div class="section-title">No Telemetry Loaded</div></div>', unsafe_allow_html=True)
    if st.button("Generate Sample Telemetry", width="stretch"):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        events = generate_events(100, 1337)
        DEFAULT_EVENTS.write_text(json.dumps(events, indent=2), encoding="utf-8")
        write_syslog(events, SAMPLE_DIR / "sample_syslog.log")
        st.rerun()


def main() -> None:
    if "dashboard_state" not in st.session_state:
        st.session_state.dashboard_state = load_dashboard_state()

    stats = live_pipeline_stats()
    service = service_snapshot()
    health_label, health_detail = service_health()
    mode_summary = runtime_mode_summary(service)
    event_files = discover_event_files()
    case_summary = case_store.summary()
    ioc_summary = ioc_store.stats()

    with st.sidebar:
        st.markdown("### Cyber-EW Fusion Cell")
        if st.button("Refresh Now", width="stretch"):
            st.rerun()
        auto_refresh = st.checkbox("Auto-refresh", value=False)
        refresh_seconds = st.number_input("Refresh seconds", min_value=5, max_value=300, value=30, step=5)
        if auto_refresh:
            st.markdown(f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">', unsafe_allow_html=True)

        selected_file = st.selectbox(
            "Telemetry",
            event_files,
            index=0 if event_files else None,
            format_func=display_path,
        )
        minimum_score = st.slider("Risk floor", 0.0, 1.0, 0.5, 0.05)
        level_filter = st.multiselect(
            "Levels",
            ["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium"],
        )
        st.divider()
        uploaded = st.file_uploader("Import JSON telemetry", type=["json"])
        if uploaded and st.button("Save Import", width="stretch"):
            save_uploaded_telemetry(uploaded)
            st.rerun()

        if st.button("Regenerate Demo Data", width="stretch"):
            SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
            events = generate_events(120, int(datetime.now().timestamp()) % 100000)
            DEFAULT_EVENTS.write_text(json.dumps(events, indent=2), encoding="utf-8")
            write_syslog(events, SAMPLE_DIR / "sample_syslog.log")
            st.rerun()

    st.markdown(
        f"""
        <div class="topbar">
            <div>
                <div class="brand-title">Cyber-EW Fusion Cell</div>
                <div class="brand-subtitle">Defensive cyber intelligence fusion and alert triage</div>
            </div>
            <div class="status-pill">{health_label} | {mode_summary["label"]}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(f'{health_detail} | Mode: {mode_summary["operation_mode"]} | Mock telemetry: {mode_summary["mock_telemetry"]}')

    if not selected_file:
        render_empty_state()
        return

    df = load_events(selected_file)
    if df.empty:
        render_empty_state()
        return

    alerts = df[(df["score"] >= minimum_score) & (df["level"].isin(level_filter))].copy()
    alert_state = st.session_state.dashboard_state.get("alerts", {})
    if not alerts.empty:
        alerts["status"] = alerts["event_id"].map(lambda alert_id: alert_state.get(alert_id, {}).get("status", "New"))
        alerts["notes"] = alerts["event_id"].map(lambda alert_id: alert_state.get(alert_id, {}).get("notes", ""))
    else:
        alerts["status"] = pd.Series(dtype="str")
        alerts["notes"] = pd.Series(dtype="str")

    critical_count = int((df["level"] == "Critical").sum())
    high_count = int((df["level"] == "High").sum())
    entity_count = len(set(df["source_ip"].dropna()) | set(df["destination_ip"].dropna()))
    detection_count = int((df["patterns"] != "Routine").sum())
    active_count = int(alerts["status"].isin(["New", "Investigating"]).sum()) if not alerts.empty else 0

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        metric_card("Events", f"{len(df):,}", f"{stats.get('events_processed', 0):,} processed by pipeline")
    with c2:
        metric_card("Alerts", f"{len(alerts):,}", f"{critical_count} critical / {high_count} high")
    with c3:
        metric_card("Detections", f"{detection_count:,}", "behavior and signature hints")
    with c4:
        metric_card("Entities", f"{entity_count:,}", "source and destination nodes")
    with c5:
        max_score = df["score"].max() if not df.empty else 0
        metric_card("Cases", f"{case_summary.get('open_cases', 0):,}", f"{case_summary.get('total_cases', 0)} total")
    with c6:
        max_score = df["score"].max() if not df.empty else 0
        metric_card("IOC Watchlist", f"{ioc_summary.get('total_iocs', 0):,}", f"peak score {max_score:.2f}")

    overview_tab, capabilities_tab, connectors_tab, hunting_tab, automation_tab, alerts_tab, cases_tab, investigation_tab, ioc_tab, entities_tab, profiles_tab, health_tab, events_tab = st.tabs(
        ["Overview", "Capabilities", "Connectors", "Hunting", "Automation", "Alert Triage", "Cases", "Investigation", "IOCs", "Entities", "Profiles", "Health", "Events"]
    )

    with overview_tab:
        left, right = st.columns([1.25, 1])
        with left:
            st.markdown('<div class="section-shell"><div class="section-title">Threat Timeline</div>', unsafe_allow_html=True)
            timeline = df.dropna(subset=["timestamp_dt"]).copy()
            if not timeline.empty:
                timeline["minute"] = timeline["timestamp_dt"].dt.floor("min")
                chart = timeline.groupby(["minute", "level"]).size().reset_index(name="events")
                st.line_chart(chart, x="minute", y="events", color="level", height=310)
            st.markdown("</div>", unsafe_allow_html=True)

        with right:
            st.markdown('<div class="section-shell"><div class="section-title">Risk Mix</div>', unsafe_allow_html=True)
            risk_mix = df["level"].value_counts().reindex(["Critical", "High", "Medium", "Low", "Info"]).fillna(0)
            st.bar_chart(risk_mix, height=310)
            st.markdown("</div>", unsafe_allow_html=True)

        l2, r2 = st.columns([1, 1])
        with l2:
            st.markdown('<div class="section-shell"><div class="section-title">Detection Families</div>', unsafe_allow_html=True)
            pattern_counts = Counter()
            for patterns in df["patterns"]:
                for pattern in str(patterns).split(", "):
                    if pattern and pattern != "Routine":
                        pattern_counts[pattern] += 1
            pattern_df = pd.DataFrame(pattern_counts.most_common(), columns=["pattern", "events"])
            st.dataframe(pattern_df, hide_index=True, width="stretch", height=240)
            st.markdown("</div>", unsafe_allow_html=True)

        with r2:
            st.markdown('<div class="section-shell"><div class="section-title">Pipeline State</div>', unsafe_allow_html=True)
            queue = stats.get("queue_status", {})
            state_df = pd.DataFrame(
                [
                    {"metric": "Threat intel matches", "value": stats.get("threat_intel_matches", 0)},
                    {"metric": "ML anomalies", "value": stats.get("ml_anomalies_detected", 0)},
                    {"metric": "Signature matches", "value": stats.get("signature_matches", 0)},
                    {"metric": "Raw queue", "value": queue.get("raw_events", 0)},
                    {"metric": "Normalized queue", "value": queue.get("normalized_events", 0)},
                    {"metric": "Scored events", "value": queue.get("scored_events", 0)},
                ]
            )
            st.dataframe(state_df, hide_index=True, width="stretch", height=240)
            st.markdown("</div>", unsafe_allow_html=True)

    with capabilities_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Sentinel-Class Capability Matrix</div>', unsafe_allow_html=True)
        capability_df = pd.DataFrame(capability_matrix(service))
        st.dataframe(capability_df, hide_index=True, width="stretch", height=360)
        st.markdown("</div>", unsafe_allow_html=True)

        c_left, c_right = st.columns([1, 1])
        with c_left:
            st.markdown('<div class="section-shell"><div class="section-title">Runtime Truth</div>', unsafe_allow_html=True)
            st.dataframe(
                pd.DataFrame(
                    [
                        {"signal": "Mode label", "value": mode_summary["label"]},
                        {"signal": "Operation mode", "value": mode_summary["operation_mode"]},
                        {"signal": "Mock telemetry", "value": mode_summary["mock_telemetry"]},
                        {"signal": "Live Windows events", "value": mode_summary["windows_events"]},
                        {"signal": "Live packet events", "value": mode_summary["packet_events"]},
                    ]
                ),
                hide_index=True,
                width="stretch",
                height=230,
            )
            st.markdown("</div>", unsafe_allow_html=True)
        with c_right:
            st.markdown('<div class="section-shell"><div class="section-title">Local Differentiators</div>', unsafe_allow_html=True)
            st.dataframe(
                pd.DataFrame(
                    [
                        {"area": "Air-gapped operation", "value": "Local storage, local API, local dashboard"},
                        {"area": "Cost control", "value": "No cloud ingestion bill for local mode"},
                        {"area": "SOC workflow", "value": "Cases, IOCs, playbooks, ATT&CK timeline"},
                        {"area": "Expansion path", "value": "Connectors and cloud AI can be added as optional modules"},
                    ]
                ),
                hide_index=True,
                width="stretch",
                height=230,
            )
            st.markdown("</div>", unsafe_allow_html=True)

    with connectors_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Live Connector Readiness</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(connector_readiness(service)), hide_index=True, width="stretch", height=380)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-shell"><div class="section-title">Connector Catalog</div>', unsafe_allow_html=True)
        connector_stats = connector_summary()
        st.caption(f'{connector_stats["implemented"]} implemented | {connector_stats["demo_blueprints"]} cloud/API blueprints | {connector_stats["total_connectors"]} total catalog entries')
        st.dataframe(pd.DataFrame(connector_catalog()), hide_index=True, width="stretch", height=420)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-shell"><div class="section-title">Setup Action Plan</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(installer_action_plan()), hide_index=True, width="stretch", height=300)
        st.markdown("</div>", unsafe_allow_html=True)

    with hunting_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Advanced Hunting</div>', unsafe_allow_html=True)
        query_text = st.text_area(
            "KQL-like query",
            value='alerts | where score >= 0.7 | project timestamp,level,score,source_ip,destination_ip,event_type | take 100',
            height=110,
        )
        q1, q2 = st.columns([1, 4])
        with q1:
            query_limit = st.number_input("Limit", min_value=10, max_value=2000, value=250, step=10)
        with q2:
            run_query = st.button("Run Hunt", width="stretch")
        if run_query:
            result = hunting_engine.execute(query_text, limit=int(query_limit))
            st.caption(f'{result["row_count"]} rows | {result["elapsed_ms"]} ms')
            st.dataframe(pd.DataFrame(result["rows"]), hide_index=True, width="stretch", height=420)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-shell"><div class="section-title">Security Lake</div>', unsafe_allow_html=True)
        lake_stats = security_lake.stats()
        st.dataframe(
            pd.DataFrame(
                [
                    {"tier": "Analytics", "path": lake_stats["analytics_tier"], "detail": json.dumps(lake_stats["tables"])},
                    {"tier": "Lake", "path": lake_stats["lake_tier"], "detail": f'{lake_stats["parquet_files"]} parquet files / {lake_stats["parquet_bytes"]} bytes'},
                ]
            ),
            hide_index=True,
            width="stretch",
            height=150,
        )
        if st.button("Create Lake Snapshot", width="stretch"):
            snapshot = security_lake.snapshot_to_lake()
            st.json(snapshot)
        st.markdown("</div>", unsafe_allow_html=True)

    with automation_tab:
        st.markdown('<div class="section-shell"><div class="section-title">SOAR Playbooks</div>', unsafe_allow_html=True)
        playbooks = playbook_engine.list_playbooks()
        playbook_df = pd.DataFrame(
            [
                {
                    "playbook_id": item["playbook_id"],
                    "name": item["name"],
                    "category": item["category"],
                    "trigger": item["trigger"],
                    "actions": len(item["actions"]),
                }
                for item in playbooks
            ]
        )
        st.caption(f"{len(playbooks)} playbooks available. Destructive actions stay dry-run unless explicitly approved.")
        st.dataframe(playbook_df, hide_index=True, width="stretch", height=360)
        selected_playbook_id = st.selectbox("Playbook", playbook_df["playbook_id"].tolist() if not playbook_df.empty else [])
        selected_playbook = next((item for item in playbooks if item["playbook_id"] == selected_playbook_id), {})
        st.json(selected_playbook)
        approve_actions = st.checkbox("Approve destructive actions", value=False)
        if st.button("Run Selected Playbook", width="stretch", disabled=not bool(selected_playbook_id)):
            alert_context = alerts.iloc[0].to_dict() if not alerts.empty else {}
            run_result = playbook_engine.run(selected_playbook_id, alert_context, approved=approve_actions)
            st.json(run_result)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-shell"><div class="section-title">Recent Automation Runs</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(playbook_engine.recent_runs(limit=50)), hide_index=True, width="stretch", height=260)
        st.markdown("</div>", unsafe_allow_html=True)

    with alerts_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Alert Queue</div>', unsafe_allow_html=True)
        f1, f2 = st.columns([1.3, 1])
        with f1:
            alert_search = st.text_input("Search alerts", placeholder="IP, user, pattern, event type")
        with f2:
            status_filter = st.multiselect("Case status", ALERT_STATUSES, default=ALERT_STATUSES)

        alert_view = alerts.copy()
        if alert_search:
            query = alert_search.lower()
            searchable = alert_view[
                ["event_id", "patterns", "source_ip", "destination_ip", "username", "event_type", "level", "status"]
            ].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            alert_view = alert_view[searchable.str.contains(query, regex=False)]
        if status_filter:
            alert_view = alert_view[alert_view["status"].isin(status_filter)]

        alert_columns = ["timestamp", "status", "level", "score", "patterns", "source_ip", "destination_ip", "port", "event_type", "username"]
        st.dataframe(alert_view[alert_columns], hide_index=True, width="stretch", height=420)
        st.markdown("</div>", unsafe_allow_html=True)

        if not alert_view.empty:
            selected_alert_id = st.selectbox("Selected alert", alert_view["event_id"].tolist())
            selected = alert_view[alert_view["event_id"] == selected_alert_id].iloc[0].to_dict()
            d1, d2 = st.columns([1, 1])
            with d1:
                st.markdown('<div class="section-shell"><div class="section-title">Alert Detail</div>', unsafe_allow_html=True)
                st.json(
                    {
                        "event_id": selected["event_id"],
                        "level": selected["level"],
                        "score": selected["score"],
                        "patterns": selected["patterns"],
                        "source_ip": selected["source_ip"],
                        "destination_ip": selected["destination_ip"],
                        "port": selected["port"],
                        "status": selected["status"],
                        "notes": selected["notes"],
                        "details": selected["details"],
                    }
                )
                st.markdown("</div>", unsafe_allow_html=True)
            with d2:
                st.markdown('<div class="section-shell"><div class="section-title">Analyst Workflow</div>', unsafe_allow_html=True)
                current_state = st.session_state.dashboard_state.get("alerts", {}).get(selected_alert_id, {})
                current_case = case_store.by_alert_id().get(selected_alert_id, {})
                selected_status = st.selectbox(
                    "Set case status",
                    ALERT_STATUSES,
                    index=ALERT_STATUSES.index(current_case.get("status", current_state.get("status", "New"))) if current_case.get("status", current_state.get("status", "New")) in ALERT_STATUSES else 0,
                )
                selected_disposition = st.selectbox(
                    "Disposition",
                    CASE_DISPOSITIONS,
                    index=CASE_DISPOSITIONS.index(current_case.get("disposition", "Undetermined")) if current_case.get("disposition", "Undetermined") in CASE_DISPOSITIONS else 0,
                )
                owner = st.text_input("Owner", value=current_case.get("owner", ""), placeholder="analyst name or shift")
                selected_playbook = st.selectbox(
                    "Response playbook",
                    list(PLAYBOOKS.keys()),
                    index=list(PLAYBOOKS.keys()).index(current_case.get("playbook", infer_playbook(selected["patterns"]))) if current_case.get("playbook", infer_playbook(selected["patterns"])) in PLAYBOOKS else 0,
                )
                analyst_notes = st.text_area(
                    "Analyst notes",
                    value=current_case.get("notes", current_state.get("notes", "")),
                    height=120,
                    placeholder="What did you verify? What action was taken?",
                )
                case_tags = st.text_input("Case tags", value=", ".join(current_case.get("tags", [])), placeholder="ransomware, endpoint, urgent")
                a1, a2, a3 = st.columns(3)
                with a1:
                    if st.button("Save Case", width="stretch"):
                        update_alert_state(selected_alert_id, selected_status, analyst_notes)
                        case_store.upsert_for_alert(
                            alert_id=selected_alert_id,
                            alert=selected,
                            status=selected_status,
                            owner=owner,
                            notes=analyst_notes,
                            disposition=selected_disposition,
                            playbook=selected_playbook,
                            tags=[tag.strip() for tag in case_tags.split(",") if tag.strip()],
                        )
                        st.rerun()
                with a2:
                    if st.button("Add Source IOC", width="stretch", disabled=not bool(selected.get("source_ip"))):
                        ioc_store.add(
                            value=str(selected["source_ip"]),
                            ioc_type="ip",
                            threat_type=str(selected["patterns"]).split(",")[0].lower().replace(" ", "_"),
                            confidence=float(selected["score"]),
                            description=f"Added from alert {selected_alert_id}",
                            tags=["dashboard", selected["level"].lower()],
                        )
                        st.rerun()
                with a3:
                    report = {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "alert": clean_for_json(selected),
                        "case": {
                            "status": selected_status,
                            "owner": owner,
                            "disposition": selected_disposition,
                            "playbook": selected_playbook,
                            "notes": analyst_notes,
                        },
                        "playbook_steps": PLAYBOOKS[selected_playbook],
                        "recommended_actions": [
                            "Validate source endpoint ownership",
                            "Inspect correlated activity for same source and user",
                            "Block confirmed malicious indicators",
                            "Preserve logs and host artifacts",
                        ],
                    }
                    st.download_button(
                        "Export Incident",
                        data=json.dumps(report, indent=2, default=str),
                        file_name=f"{selected_alert_id}_incident.json",
                        mime="application/json",
                        width="stretch",
                    )

                action_df = pd.DataFrame(
                    [{"step": index + 1, "action": action} for index, action in enumerate(PLAYBOOKS[selected_playbook])]
                )
                st.dataframe(action_df, hide_index=True, width="stretch", height=250)
                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.info("No alerts match the current filters.")

    with cases_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Case Board</div>', unsafe_allow_html=True)
        cases_df = load_cases()
        if cases_df.empty:
            st.info("No saved cases yet. Save an alert from Alert Triage to open a case.")
        else:
            status_order = {name: index for index, name in enumerate(ALERT_STATUSES)}
            cases_df["status_order"] = cases_df["status"].map(lambda value: status_order.get(value, 99))
            board = cases_df.sort_values(["status_order", "score", "updated_at"], ascending=[True, False, False])
            st.dataframe(
                board.drop(columns=["history", "status_order"], errors="ignore"),
                hide_index=True,
                width="stretch",
                height=380,
            )
            b1, b2, b3, b4 = st.columns(4)
            with b1:
                st.metric("Open", case_summary.get("open_cases", 0))
            with b2:
                st.metric("True Positive", case_summary.get("by_status", {}).get("Contained", 0) + int((cases_df.get("disposition", pd.Series(dtype=str)) == "True Positive").sum()))
            with b3:
                st.metric("False Positive", int((cases_df.get("disposition", pd.Series(dtype=str)) == "False Positive").sum()))
            with b4:
                st.metric("Assigned", int(cases_df.get("owner", pd.Series(dtype=str)).replace("", pd.NA).dropna().count()))

            selected_case_id = st.selectbox("Case detail", board["case_id"].tolist())
            case_detail = case_store.get(selected_case_id) or {}
            st.json(clean_for_json(case_detail))
            st.download_button(
                "Export Case Bundle",
                data=json.dumps(clean_for_json(case_detail), indent=2, default=str),
                file_name=f"{selected_case_id}.json",
                mime="application/json",
                width="stretch",
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with investigation_tab:
        st.markdown('<div class="section-shell"><div class="section-title">ATT&CK Investigation Timeline</div>', unsafe_allow_html=True)
        hunt_query = st.text_input("Hunt query", placeholder="Search by IP, username, process, filename, pattern")
        entity_options = sorted(
            set(df["source_ip"].replace("", pd.NA).dropna().tolist())
            | set(df["destination_ip"].replace("", pd.NA).dropna().tolist())
            | set(df["username"].replace("", pd.NA).dropna().tolist())
        )
        selected_entity = st.selectbox("Pivot entity", [""] + entity_options)

        hunt_df = df.copy()
        if selected_entity:
            hunt_df = hunt_df[
                (hunt_df["source_ip"] == selected_entity)
                | (hunt_df["destination_ip"] == selected_entity)
                | (hunt_df["username"] == selected_entity)
            ]
        if hunt_query:
            query = hunt_query.lower()
            searchable = hunt_df[
                ["event_id", "patterns", "source_ip", "destination_ip", "username", "event_type", "process_name", "file_path"]
            ].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            hunt_df = hunt_df[searchable.str.contains(query, regex=False)]

        attack_timeline = pd.DataFrame(build_attack_timeline(hunt_df.drop(columns=["timestamp_dt"], errors="ignore").to_dict("records")))
        attack_report = build_investigation_report(
            hunt_df.drop(columns=["timestamp_dt"], errors="ignore").to_dict("records"),
            selected_entity or hunt_query or "all telemetry",
        )

        h1, h2, h3, h4 = st.columns(4)
        with h1:
            st.metric("Matched Events", len(hunt_df))
        with h2:
            st.metric("Peak Risk", f"{hunt_df['score'].max():.2f}" if not hunt_df.empty else "0.00")
        with h3:
            st.metric("ATT&CK Tactics", attack_timeline["tactic"].nunique() if not attack_timeline.empty else 0)
        with h4:
            st.metric("Techniques", attack_timeline["technique_id"].nunique() if not attack_timeline.empty else 0)

        if not hunt_df.empty:
            if not attack_timeline.empty:
                attack_timeline["timestamp_dt"] = pd.to_datetime(attack_timeline["timestamp"], errors="coerce", utc=True)
                attack_timeline["minute"] = attack_timeline["timestamp_dt"].dt.floor("min")
                st.line_chart(
                    attack_timeline.groupby(["minute", "tactic"]).size().reset_index(name="events"),
                    x="minute",
                    y="events",
                    color="tactic",
                    height=250,
                )
                st.dataframe(
                    attack_timeline[
                        [
                            "timestamp",
                            "tactic",
                            "technique_id",
                            "technique",
                            "level",
                            "score",
                            "source_ip",
                            "destination_ip",
                            "username",
                            "evidence",
                        ]
                    ],
                    hide_index=True,
                    width="stretch",
                    height=300,
                )
                r1, r2 = st.columns(2)
                with r1:
                    st.download_button(
                        "Export ATT&CK Timeline",
                        data=attack_timeline.drop(columns=["timestamp_dt"], errors="ignore").to_csv(index=False),
                        file_name="attack_timeline.csv",
                        mime="text/csv",
                        width="stretch",
                    )
                with r2:
                    st.download_button(
                        "Export Investigation Report",
                        data=json.dumps(clean_for_json(attack_report), indent=2, default=str),
                        file_name="investigation_report.json",
                        mime="application/json",
                        width="stretch",
                    )
            else:
                st.info("No ATT&CK-mapped activity in the current hunt scope.")

            st.markdown('<div class="section-title">Raw Hunt Evidence</div>', unsafe_allow_html=True)
            st.dataframe(
                hunt_df[["timestamp", "level", "score", "patterns", "source_ip", "destination_ip", "username", "event_type", "file_path"]],
                hide_index=True,
                width="stretch",
                height=260,
            )
            st.download_button(
                "Export Hunt Results",
                data=hunt_df.drop(columns=["timestamp_dt"], errors="ignore").to_csv(index=False),
                file_name="hunt_results.csv",
                mime="text/csv",
                width="stretch",
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with ioc_tab:
        st.markdown('<div class="section-shell"><div class="section-title">IOC Watchlist</div>', unsafe_allow_html=True)
        ioc_df = load_iocs()
        i1, i2, i3, i4 = st.columns(4)
        with i1:
            new_value = st.text_input("IOC value", placeholder="IP, domain, URL, hash, username")
        with i2:
            new_type = st.selectbox("Type", ["ip", "domain", "url", "hash", "user", "file"])
        with i3:
            new_threat = st.text_input("Threat type", value="watchlist")
        with i4:
            new_confidence = st.slider("Confidence", 0.0, 1.0, 0.75, 0.05)
        ioc_description = st.text_input("Description", placeholder="Why this indicator matters")
        ioc_tags = st.text_input("IOC tags", placeholder="c2, ransomware, blocked")
        if st.button("Add IOC", width="stretch"):
            try:
                ioc_store.add(
                    value=new_value,
                    ioc_type=new_type,
                    threat_type=new_threat,
                    confidence=new_confidence,
                    description=ioc_description,
                    tags=[tag.strip() for tag in ioc_tags.split(",") if tag.strip()],
                )
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

        if ioc_df.empty:
            st.info("No local IOCs yet.")
        else:
            st.dataframe(ioc_df, hide_index=True, width="stretch", height=280)

        if not df.empty:
            matches = []
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                for ioc in ioc_store.match_event(row_dict):
                    matches.append(
                        {
                            "timestamp": row_dict.get("timestamp"),
                            "event_id": row_dict.get("event_id"),
                            "ioc": ioc.get("value"),
                            "ioc_type": ioc.get("ioc_type"),
                            "threat_type": ioc.get("threat_type"),
                            "source_ip": row_dict.get("source_ip"),
                            "destination_ip": row_dict.get("destination_ip"),
                            "score": row_dict.get("score"),
                        }
                    )
            st.markdown('<div class="section-title">IOC Matches In Loaded Telemetry</div>', unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(matches), hide_index=True, width="stretch", height=260)
        st.markdown("</div>", unsafe_allow_html=True)

    with entities_tab:
        source_counts = df["source_ip"].replace("", pd.NA).dropna().value_counts().head(25).reset_index()
        source_counts.columns = ["source_ip", "events"]
        source_risk = df.groupby("source_ip", dropna=True)["score"].max().reset_index(name="peak_score")
        source_table = source_counts.merge(source_risk, on="source_ip", how="left").sort_values(["peak_score", "events"], ascending=False)

        e1, e2 = st.columns([1.05, 1])
        with e1:
            st.markdown('<div class="section-shell"><div class="section-title">Source Entities</div>', unsafe_allow_html=True)
            st.dataframe(source_table, hide_index=True, width="stretch", height=410)
            st.markdown("</div>", unsafe_allow_html=True)
        with e2:
            st.markdown('<div class="section-shell"><div class="section-title">Destination Ports</div>', unsafe_allow_html=True)
            ports = df["port"].dropna().astype(int).value_counts().head(20)
            st.bar_chart(ports, height=410)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-shell"><div class="section-title">Communication Pairs</div>', unsafe_allow_html=True)
        pairs = (
            df.groupby(["source_ip", "destination_ip"], dropna=False)
            .agg(events=("event_id", "count"), peak_score=("score", "max"), bytes=("total_bytes", "sum"))
            .reset_index()
            .sort_values(["peak_score", "events"], ascending=False)
            .head(50)
        )
        st.dataframe(pairs, hide_index=True, width="stretch", height=340)
        st.markdown("</div>", unsafe_allow_html=True)

    with profiles_tab:
        profile_df = load_profiles()
        st.markdown('<div class="section-shell"><div class="section-title">Behavioral Baselines</div>', unsafe_allow_html=True)
        if profile_df.empty:
            st.info("No behavior profiles are persisted yet.")
        else:
            st.dataframe(
                profile_df.sort_values(["events", "entity_id"], ascending=[False, True]),
                hide_index=True,
                width="stretch",
                height=460,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with health_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Operational Readiness</div>', unsafe_allow_html=True)
        engine_stats = stats.get("engine_stats", {}) if isinstance(stats, dict) else {}
        readiness = pd.DataFrame(
            [
                {"component": "Live service", "status": health_label, "detail": health_detail},
                {"component": "Service PID", "status": str(service.get("service_pid", "")), "detail": "Process writing heartbeat"},
                {"component": "Dashboard PID", "status": str(service.get("dashboard_pid", "")), "detail": "Streamlit process"},
                {"component": "API PID", "status": str(service.get("api_pid", "")), "detail": "FastAPI process"},
                {"component": "Persisted alerts", "status": str(service.get("persisted_alerts", 0)), "detail": "Unique alert records"},
                {"component": "ML anomaly engine", "status": "Ready" if engine_stats.get("ml_anomaly_engine", {}).get("ml_available") else "Fallback", "detail": f"models trained: {engine_stats.get('ml_anomaly_engine', {}).get('models_trained')}"},
                {"component": "YARA signatures", "status": "Ready" if engine_stats.get("signature_engine", {}).get("yara_available") else "Fallback", "detail": "Fallback signatures remain active without YARA"},
                {"component": "Threat intel", "status": str(engine_stats.get("threat_intel_engine", {}).get("total_iocs", 0)), "detail": "Loaded IOCs"},
            ]
        )
        st.dataframe(readiness, hide_index=True, width="stretch", height=300)
        hleft, hright = st.columns([1, 1])
        with hleft:
            st.markdown('<div class="section-title">Queue Depth</div>', unsafe_allow_html=True)
            queue_df = pd.DataFrame([{"queue": key, "depth": value} for key, value in stats.get("queue_status", {}).items()])
            st.bar_chart(queue_df, x="queue", y="depth", height=240)
        with hright:
            st.markdown('<div class="section-title">Recent Audit Trail</div>', unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(audit_log.recent(limit=25)), hide_index=True, width="stretch", height=240)
        st.download_button(
            "Export SOC Bundle",
            data=json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "service": service,
                    "cases": case_store.all(),
                    "iocs": ioc_store.all(),
                    "audit": audit_log.recent(limit=200),
                },
                indent=2,
                default=str,
            ),
            file_name="cyber_ew_soc_bundle.json",
            mime="application/json",
            width="stretch",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with events_tab:
        st.markdown('<div class="section-shell"><div class="section-title">Event Explorer</div>', unsafe_allow_html=True)
        event_type_filter = st.multiselect("Event types", sorted(df["event_type"].dropna().unique().tolist()))
        explorer = df.copy()
        if event_type_filter:
            explorer = explorer[explorer["event_type"].isin(event_type_filter)]
        explorer_columns = [
            "timestamp",
            "event_id",
            "event_type",
            "severity",
            "level",
            "score",
            "source_ip",
            "destination_ip",
            "port",
            "protocol",
            "patterns",
        ]
        st.dataframe(explorer[explorer_columns], hide_index=True, width="stretch", height=560)
        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()

