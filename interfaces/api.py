#!/usr/bin/env python3
"""
REST API for Cyber-EW Fusion Cell.

This API exposes read-only operational telemetry by default and supports local
case/IOC updates. If CYBER_EW_API_KEY is set, mutating requests require the
same value in the X-API-Key header.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.attack_timeline import build_attack_timeline, build_investigation_report
from core.capability_center import capability_matrix, connector_readiness, installer_action_plan, runtime_mode_summary
from core.connectors.catalog import connector_catalog, connector_summary
from core.soar_engine import PlaybookEngine
from config.settings import CONFIG
from storage import AlertStore, AuditLog, CaseStore, HuntingQueryEngine, IOCStore, SecurityLake


DATA_DIR = CONFIG.data_dir
ALERTS_PATH = DATA_DIR / "outputs" / "alerts.jsonl"
SERVICE_STATUS = DATA_DIR / "outputs" / "service_status.json"
PIPELINE_STATS = DATA_DIR / "pipeline_stats.json"

alert_store = AlertStore(ALERTS_PATH)
audit_log = AuditLog(DATA_DIR / "outputs" / "audit_log.jsonl")
case_store = CaseStore(DATA_DIR / "outputs" / "cases.json", audit_log)
ioc_store = IOCStore(DATA_DIR / "threat_intel" / "local_iocs.json", audit_log)
security_lake = SecurityLake(DATA_DIR)
hunting_engine = HuntingQueryEngine(security_lake)
playbook_engine = PlaybookEngine(audit_log)

app = FastAPI(
    title="Cyber-EW Fusion Cell API",
    version="1.1.0",
    description="Local SOC API for alerts, cases, IOCs, and service health.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8501", "http://localhost:8501"],
    allow_origin_regex=r"http://(127\.0\.0\.1|localhost):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CaseUpdate(BaseModel):
    alert_id: str
    alert: Dict[str, Any] = Field(default_factory=dict)
    status: str = "New"
    owner: str = ""
    notes: str = ""
    disposition: str = "Undetermined"
    playbook: str = ""
    tags: List[str] = Field(default_factory=list)


class IOCRequest(BaseModel):
    value: str
    ioc_type: str = "ip"
    threat_type: str = "watchlist"
    confidence: float = 0.7
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    source: str = "api"


class QueryRequest(BaseModel):
    query: str = "alerts | take 100"
    limit: int = 250


class PlaybookRunRequest(BaseModel):
    playbook_id: str
    alert: Dict[str, Any] = Field(default_factory=dict)
    approved: bool = False
    actor: str = "local-analyst"


def read_json(path: Path, fallback: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    return fallback


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = os.environ.get("CYBER_EW_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def service_status() -> Dict[str, Any]:
    return read_json(SERVICE_STATUS, {})


def heartbeat_age_seconds(status: Dict[str, Any]) -> Optional[float]:
    updated = status.get("updated_at")
    if not updated:
        return None
    try:
        timestamp = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds()
    except ValueError:
        return None


@app.get("/health")
def health() -> Dict[str, Any]:
    status = service_status()
    age = heartbeat_age_seconds(status)
    running = status.get("status") == "running" and age is not None and age <= 15
    return {
        "status": "ok" if running else "degraded",
        "live_service": running,
        "heartbeat_age_seconds": age,
        "service_pid": status.get("service_pid"),
        "dashboard_pid": status.get("dashboard_pid"),
        "api_pid": status.get("api_pid"),
        "persisted_alerts": alert_store.count(),
    }


@app.get("/readiness")
def readiness() -> Dict[str, Any]:
    status = service_status()
    pipeline = status.get("pipeline", {}) if isinstance(status, dict) else {}
    engine_stats = pipeline.get("engine_stats", {}) if isinstance(pipeline, dict) else {}
    return {
        "ready": ALERTS_PATH.parent.exists(),
        "storage": {
            "alerts_path": str(ALERTS_PATH),
            "alerts_writable": ALERTS_PATH.parent.exists(),
            "cases_path": str(case_store.path),
        },
        "engines": {
            "ml_available": engine_stats.get("ml_anomaly_engine", {}).get("ml_available"),
            "ml_models_trained": engine_stats.get("ml_anomaly_engine", {}).get("models_trained"),
            "yara_available": engine_stats.get("signature_engine", {}).get("yara_available"),
        },
    }


@app.get("/metrics")
def metrics() -> Dict[str, Any]:
    status = service_status()
    pipeline = status.get("pipeline", {}) if isinstance(status, dict) else {}
    return {
        "pipeline": pipeline,
        "cases": case_store.summary(),
        "iocs": ioc_store.stats(),
        "persisted_alerts": alert_store.count(),
    }


@app.get("/capabilities")
def capabilities() -> Dict[str, Any]:
    status = service_status()
    return {
        "runtime": runtime_mode_summary(status),
        "capabilities": capability_matrix(status),
        "connectors": connector_summary(),
        "setup_plan": installer_action_plan(),
    }


@app.get("/connectors")
def connectors() -> Dict[str, Any]:
    return {
        "summary": connector_summary(),
        "readiness": connector_readiness(service_status()),
        "catalog": connector_catalog(),
    }


@app.get("/lake/stats")
def lake_stats() -> Dict[str, Any]:
    return security_lake.stats()


@app.post("/lake/snapshot", dependencies=[Depends(require_api_key)])
def lake_snapshot() -> Dict[str, Any]:
    return security_lake.snapshot_to_lake()


@app.post("/hunt/query")
def hunt_query(payload: QueryRequest) -> Dict[str, Any]:
    return hunting_engine.execute(payload.query, limit=payload.limit)


@app.get("/playbooks")
def playbooks() -> List[Dict[str, Any]]:
    return playbook_engine.list_playbooks()


@app.get("/playbooks/runs")
def playbook_runs(limit: int = Query(default=100, ge=1, le=500)) -> List[Dict[str, Any]]:
    return playbook_engine.recent_runs(limit=limit)


@app.post("/playbooks/run", dependencies=[Depends(require_api_key)])
def run_playbook(payload: PlaybookRunRequest) -> Dict[str, Any]:
    try:
        return playbook_engine.run(payload.playbook_id, payload.alert, payload.approved, payload.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/alerts")
def alerts(limit: int = Query(default=100, ge=1, le=500), level: Optional[str] = None) -> List[Dict[str, Any]]:
    records = alert_store.recent(limit=limit)
    if level:
        records = [item for item in records if str(item.get("threat_level", "")).lower() == level.lower()]
    return records


@app.get("/attack/timeline")
def attack_timeline(limit: int = Query(default=250, ge=1, le=1000), scope: str = "") -> Dict[str, Any]:
    records = alert_store.recent(limit=limit)
    if scope:
        lowered = scope.lower()
        records = [record for record in records if lowered in json.dumps(record, default=str).lower()]
    return build_investigation_report(records, scope or "recent alerts")


@app.get("/cases")
def cases() -> List[Dict[str, Any]]:
    return case_store.all()


@app.post("/cases", dependencies=[Depends(require_api_key)])
def upsert_case(payload: CaseUpdate) -> Dict[str, Any]:
    return case_store.upsert_for_alert(
        alert_id=payload.alert_id,
        alert=payload.alert,
        status=payload.status,
        owner=payload.owner,
        notes=payload.notes,
        disposition=payload.disposition,
        playbook=payload.playbook,
        tags=payload.tags,
    )


@app.get("/iocs")
def iocs() -> List[Dict[str, Any]]:
    return ioc_store.all()


@app.post("/iocs", dependencies=[Depends(require_api_key)])
def add_ioc(payload: IOCRequest) -> Dict[str, Any]:
    try:
        return ioc_store.add(
            value=payload.value,
            ioc_type=payload.ioc_type,
            threat_type=payload.threat_type,
            confidence=payload.confidence,
            description=payload.description,
            tags=payload.tags,
            source=payload.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/audit")
def audit(limit: int = Query(default=100, ge=1, le=500)) -> List[Dict[str, Any]]:
    return audit_log.recent(limit=limit)


@app.get("/export/bundle")
def export_bundle() -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "health": health(),
        "metrics": metrics(),
        "alerts": alert_store.recent(limit=500),
        "cases": case_store.all(),
        "iocs": ioc_store.all(),
        "audit": audit_log.recent(limit=500),
    }
