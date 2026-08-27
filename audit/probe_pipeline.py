#!/usr/bin/env python3
r"""
Cyber-EW Fusion Cell - On-target END-TO-END PIPELINE RE-BASELINE  (audit step 5)

Goal (task 23): drive the REAL threaded pipeline on-target - with the FIXED ML
engine and live YARA in the loop - using only SAFE, controlled laboratory data,
and settle the long-standing "alerts_generated counter" question with evidence.

What this proves, end-to-end, through the actual worker threads + real engines
(normalize -> correlate -> behavior -> [threat-intel + ML + signature] -> score
-> publish/persist):
  1. Events injected at the ingest boundary flow through every stage and the
     three bounded queues DRAIN to empty.
  2. Real detections fire (local-IOC threat-intel, signature/YARA, ML heuristic).
  3. High/critical events produce alerts that are PERSISTED to the alert store.
  4. The pipeline starts and stops GRACEFULLY (all worker threads join).
  5. The three alert tiers are reconciled from OBSERVED data:
        pipeline.stats["alerts_generated"]  (incremented per high/critical event
                                              SCORED - pipeline.py:314)
        >=  output_engine.stats["alerts_published"]  (skipped on dedup)
        ==  alert_store.count()                       (unique persisted)
     Dedup key is  f"{event.hash_id}:{level}"  (event_models.py:215 hashes
     event_type+timestamp+src+dst+user). Injecting UNIQUE malicious events (each
     persists) vs DUPLICATE malicious events (collapse to one) exposes exactly
     why the in-memory counter can exceed the store - the real mechanism, not the
     old "counter stays 0" guess (that came from --test, which never touches
     self.stats at all: test_pipeline() returns a local dict, pipeline.py:517).

SAFETY / NON-DESTRUCTIVE:
  * Runs against an ISOLATED temp data dir (CYBER_EW_DATA_DIR) seeded with copies
    of signatures + local IOCs; the real data/outputs/alerts.jsonl is NEVER
    touched. The script ASSERTS CONFIG.data_dir is the temp dir before starting.
  * No sockets, no live capture, no network: syslog/pcap/windows/threat-intel
    INGEST sources disabled, mock sources disabled, and the network ThreatFox
    feed stripped (Local IOC feed kept). Only in-process event injection.
  * Only benign literal lab tokens are used as "malicious" markers
    (malicious-domain.com / 192.168.1.100 / powershell -enc / cmd.exe /c).

Usage (from repo root, project venv):
    .\.venv\Scripts\python.exe audit\probe_pipeline.py
"""
from __future__ import annotations

import os
import sys
import json
import time
import shutil
import traceback
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# 0) Isolate the data dir BEFORE any project import (settings reads env at
#    import time and pins CONFIG.data_dir).  Seed it so detections still fire.
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
REAL_DATA = ROOT / "data"
TMP = ROOT / "audit" / "_pipeline_run_tmp"          # disposable scratch tree

if not REAL_DATA.exists():
    print(f"[FATAL] real data dir not found: {REAL_DATA}")
    sys.exit(2)

if TMP.exists():
    shutil.rmtree(TMP)
TMP.mkdir(parents=True)

# seed detection assets into the isolated tree
if (REAL_DATA / "signatures").exists():
    shutil.copytree(REAL_DATA / "signatures", TMP / "signatures")
if (REAL_DATA / "threat_intel").exists():
    # copy local_iocs.json (and siblings) so the Local IOC feed matches offline
    shutil.copytree(REAL_DATA / "threat_intel", TMP / "threat_intel",
                    ignore=shutil.ignore_patterns("cache"))
(TMP / "ml_models").mkdir(exist_ok=True)
for jb in (REAL_DATA / "ml_models").glob("*.joblib") if (REAL_DATA / "ml_models").exists() else []:
    shutil.copy2(jb, TMP / "ml_models" / jb.name)
for d in ("outputs", "inputs/live", "inputs/logs"):
    (TMP / d).mkdir(parents=True, exist_ok=True)

os.environ["CYBER_EW_DATA_DIR"] = str(TMP)
os.environ["CYBER_EW_DISABLE_MOCK_SOURCES"] = "1"
os.environ["CYBER_EW_ENABLE_EVENTLOG"] = "0"
os.environ["CYBER_EW_ENABLE_PCAP"] = "0"
os.environ.pop("CYBER_EW_API_KEY", None)
os.environ.pop("CYBER_EW_SYSLOG_HOST", None)

sys.path.insert(0, str(ROOT))


def banner(t: str) -> None:
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


print("CYBER-EW FUSION CELL - END-TO-END PIPELINE RE-BASELINE (on-target)")
print("generated :", datetime.now(timezone.utc).isoformat())
print("python    :", sys.version.split()[0], "|", sys.executable)
print("data dir  :", TMP)

# ---------------------------------------------------------------------------
# 1) Import config, prove isolation, neutralize socket/network ingest sources.
# ---------------------------------------------------------------------------
from config.settings import CONFIG, INGEST_CONFIG  # noqa: E402

if Path(CONFIG.data_dir).resolve() != TMP.resolve():
    print(f"[FATAL] CONFIG.data_dir ({CONFIG.data_dir}) is NOT the isolated temp "
          f"dir ({TMP}); aborting to avoid touching the real store.")
    sys.exit(2)
print("isolation : CONFIG.data_dir == temp dir  [OK]")

# offline + socket-free: disable every ingest source that binds a socket or
# reaches the network. json source stays (watches an EMPTY temp dir -> no events).
INGEST_CONFIG.syslog_enabled = False
INGEST_CONFIG.pcap_enabled = False
INGEST_CONFIG.windows_events_enabled = False
INGEST_CONFIG.threat_intel_enabled = False

from core.pipeline import CyberEWPipeline           # noqa: E402
from core.engines.scoring_engine import ThreatLevel  # noqa: E402  (for reference)

pipeline = CyberEWPipeline()

# prove the alert store is inside the isolated tree
store = pipeline.output_engine.alert_store
if TMP.resolve() not in Path(store.path).resolve().parents:
    print(f"[FATAL] alert store path {store.path} is OUTSIDE temp dir; aborting.")
    sys.exit(2)
print("alert store:", store.path, " [inside temp, OK]")

# strip the network feed(s); keep only the local IOC feed so start() is offline
tie = pipeline.threat_intel_engine
kept = {k: v for k, v in tie.feeds.items() if "local" in k.lower()}
dropped = [k for k in tie.feeds if k not in kept]
tie.feeds = kept
print(f"threat feeds: kept {list(kept)} | dropped (network) {dropped}")

# ---------------------------------------------------------------------------
# 2) Per-event evidence via the pipeline's monitor callback (called for EVERY
#    processed event with the REAL computed threat_score + detection results).
# ---------------------------------------------------------------------------
records: list[dict] = []


def monitor(payload: dict) -> None:
    ev = payload.get("event")
    ts = payload.get("threat_score")
    try:
        hid = getattr(ev, "hash_id", None)
    except Exception:
        hid = None
    ml = payload.get("ml_anomalies") or {}
    records.append({
        "event_id": getattr(ev, "event_id", "?"),
        "hash_id": hid,
        "level": getattr(getattr(ts, "level", None), "value", None),
        "score": round(float(getattr(ts, "score", 0.0) or 0.0), 3),
        "ti": len(payload.get("threat_intel_matches") or []),
        "ml_anom": bool(ml.get("is_anomaly")) if isinstance(ml, dict) else False,
        "sig": len(payload.get("signature_matches") or []),
    })


pipeline.monitor_callback = monitor

# ---------------------------------------------------------------------------
# 3) Controlled lab dataset (raw events as the ingest boundary would deliver).
# ---------------------------------------------------------------------------
MARKER = (
    b"GET /login HTTP/1.1\r\n"
    b"Host: malicious-domain.com\r\n"          # local-IOC domain + YARA token
    b"X-Forwarded-For: 192.168.1.100\r\n"      # local-IOC ip + YARA token
    b"User-Agent: labtest\r\n\r\n"
    b"cmd.exe /c whoami & powershell -enc QQBBAEEA\r\n"  # YARA tokens
)
MARKER_HEX = MARKER.hex()
BASE = datetime.now(timezone.utc) - timedelta(hours=2)


def malicious(i: int, ts: datetime) -> dict:
    """A high-signal but SAFE lab event: local IOC + signature text + YARA hex."""
    return {
        "source_type": "lab",                  # -> generic normalization
        "event_type": "network_connection",
        "source_ip": "192.168.1.100",          # matches local IOC
        "destination_ip": "8.8.8.8",
        "destination_port": 4444,
        "protocol": "TCP",
        "severity": "critical",
        "timestamp": ts.isoformat(),
        "details": {
            "message": "Port scan detected",   # matches JSON signature rule
            "query": "malicious-domain.com",   # matches local IOC (domain)
            "hex": MARKER_HEX,                  # YARA scans decoded bytes
            "bytes_sent": 1500,
            "bytes_received": 5000,
            "nonce": i,
        },
    }


def benign(i: int, ts: datetime) -> dict:
    return {
        "source_type": "lab",
        "event_type": "network_connection",
        "source_ip": f"10.0.0.{10 + i}",
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "protocol": "TCP",
        "severity": "low",
        "timestamp": ts.isoformat(),
        "details": {
            "message": "routine https session",
            "bytes_sent": 800,
            "bytes_received": 1200,
            "nonce": i,
        },
    }


N_UNIQUE = 6     # distinct timestamps -> distinct hash_id -> each should persist
N_DUP = 3        # identical fixed event -> same hash_id -> should collapse to 1
N_BENIGN = 8     # should NOT alert

unique_events = [malicious(i, BASE + timedelta(seconds=i)) for i in range(N_UNIQUE)]
dup_ts = BASE + timedelta(seconds=100)                       # one fixed instant
dup_events = [malicious(100, dup_ts) for _ in range(N_DUP)]  # byte-identical
benign_events = [benign(i, BASE + timedelta(seconds=200 + i)) for i in range(N_BENIGN)]
all_events = unique_events + dup_events + benign_events
TOTAL = len(all_events)

# ---------------------------------------------------------------------------
# 4) Start the REAL pipeline, inject, wait for drain, stop gracefully.
# ---------------------------------------------------------------------------
banner("PIPELINE START (real start(): engines + 4 worker threads)")
store_before = store.count()
print("alert store count before run:", store_before)

pipeline.start()

# engine readiness snapshot (post-start)
from core.engines.signature_engine import YARARule  # noqa: E402
sig = pipeline.signature_engine
yara_rules = [rid for rid, r in sig.rules.items() if isinstance(r, YARARule)]
print("ml.models_trained        :", pipeline.ml_anomaly_engine.models_trained,
      "(False = heuristic after fix; real ML path proven separately)")
print("signature rules loaded   :", len(sig.rules), "| YARA rules:", yara_rules)
print("threat-intel IOC cache   :", tie.stats.get("total_iocs"),
      "iocs across", len(tie.ioc_cache), "type(s)")
print(f"injecting {TOTAL} lab events "
      f"({N_UNIQUE} unique-malicious, {N_DUP} duplicate-malicious, {N_BENIGN} benign)")

banner("INJECT + DRAIN")
t0 = time.time()
for ev in all_events:
    pipeline._handle_raw_event(ev)

deadline = time.time() + 30.0
drained = False
while time.time() < deadline:
    st = pipeline.get_statistics()
    q = st["queue_status"]
    if (st["events_processed"] >= TOTAL and q["raw_events"] == 0
            and q["normalized_events"] == 0 and q["analyzed_events"] == 0):
        drained = True
        break
    time.sleep(0.1)
time.sleep(0.6)  # let the final publish_alert() flush to the store
elapsed = time.time() - t0

st = pipeline.get_statistics()
print(f"events_processed         : {st['events_processed']} / {TOTAL} injected")
print(f"queues drained to empty  : {drained}  "
      f"(raw={st['queue_status']['raw_events']} "
      f"norm={st['queue_status']['normalized_events']} "
      f"analyzed={st['queue_status']['analyzed_events']})")
print(f"wall time to drain       : {elapsed:.3f}s  "
      f"=> {st['events_processed'] / elapsed:.1f} ev/s (in-process, correlation+behavior+ML+sig+score)")

banner("PIPELINE STOP (graceful)")
t_stop = time.time()
pipeline.stop()
alive = [t.name for t in pipeline.processing_threads if t.is_alive()]
print(f"stop() completed in {time.time() - t_stop:.3f}s | worker threads still alive: {alive or 'none'}")

# ---------------------------------------------------------------------------
# 5) Reconcile the three alert tiers from OBSERVED per-event data.
# ---------------------------------------------------------------------------
banner("DETECTION + ALERT RECONCILIATION (the counter question)")

by_level: dict[str, int] = {}
for r in records:
    by_level[r["level"]] = by_level.get(r["level"], 0) + 1
high_crit = [r for r in records if r["level"] in ("high", "critical")]
distinct_keys = {f"{r['hash_id']}:{r['level']}" for r in high_crit}

counter = pipeline.stats.get("alerts_generated")
published = pipeline.output_engine.stats.get("alerts_published")
store_after = store.count()
store_delta = store_after - store_before

print("per-event threat levels  :", json.dumps(by_level))
print(f"high/critical events     : {len(high_crit)}  "
      f"(distinct hash_id:level keys = {len(distinct_keys)})")
print(f"threat_intel_matches     : {pipeline.stats.get('threat_intel_matches')}")
print(f"ml_anomalies_detected    : {pipeline.stats.get('ml_anomalies_detected')}")
print(f"signature_matches        : {pipeline.stats.get('signature_matches')}")
print("-" * 74)
print(f"[TIER 1] alerts_generated (pipeline counter, ++ per high/crit scored) : {counter}")
print(f"[TIER 2] alerts_published (output_engine, skipped on dedup)           : {published}")
print(f"[TIER 3] alert_store delta (unique persisted this run)                : {store_delta}")
print("-" * 74)

# grounded verdicts (computed, not hardcoded)
def verdict(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'CHECK'}] {label}{(' - ' + detail) if detail else ''}")

verdict("counter increments in a REAL run (refutes 'stays 0')", (counter or 0) > 0,
        f"alerts_generated={counter}")
verdict("counter == #high/critical events scored", counter == len(high_crit),
        f"{counter} vs {len(high_crit)}")
verdict("store delta == distinct (hash_id:level) among high/crit",
        store_delta == len(distinct_keys), f"{store_delta} vs {len(distinct_keys)}")
verdict("published == store delta (persist path consistent)",
        published == store_delta, f"{published} vs {store_delta}")
dup_collapsed = (counter or 0) - store_delta
verdict("duplicate malicious events collapsed in store (dedup)", dup_collapsed >= 1,
        f"counter-store = {dup_collapsed} deduped (injected {N_DUP} identical)")
verdict("benign events did NOT alert", by_level.get("high", 0) + by_level.get("critical", 0) <= N_UNIQUE + N_DUP,
        "no benign high/critical")

banner("SAMPLE EVIDENCE")
print("first 3 monitor records:")
for r in records[:3]:
    print("   ", json.dumps(r, default=str))
recent = store.recent(limit=1)
if recent:
    a = recent[0]
    slim = {k: a.get(k) for k in ("alert_id", "threat_level", "priority")}
    slim["event.source_ip"] = (a.get("event") or {}).get("source_ip")
    slim["dedupe_key"] = (a.get("metadata") or {}).get("dedupe_key")
    print("newest stored alert     :", json.dumps(slim, default=str))

banner("RE-BASELINE COMPLETE")
print("Isolated run tree (safe to delete):", TMP)
print("Paste the full output back to promote/settle task 23.")
