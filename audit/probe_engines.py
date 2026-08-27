#!/usr/bin/env python3
r"""
Cyber-EW Fusion Cell - On-target Engine Verification  (audit harness, step 2)

Proves two things the sandbox could not, using only SAFE synthetic lab data:

  A) ML: the IsolationForest code path actually works WHEN GENUINELY TRAINED.
     The probe already showed the *shipped* model is unfitted -> heuristic
     fallback. Here we feed >=100 synthetic benign events, train in-memory, and
     confirm detect_anomalies then takes the REAL isolation_forest branch. This
     separates "shipped artifact is hollow" (a defect) from "ML is broken" (it
     is not). NON-DESTRUCTIVE: _save_models is patched to a no-op so the shipped
     .joblib on disk is NOT overwritten by this diagnostic.

  B) YARA: the loaded .yar rules actually MATCH. We build a benign synthetic
     network payload containing the literal marker tokens the shipped rules key
     on (malicious-domain.com / 192.168.1.100 / powershell -enc / cmd.exe /c).
     These are literal strings, not malware - safe controlled lab data.

Usage (from repo root, project venv):
    .\.venv\Scripts\python.exe audit\probe_engines.py
"""
from __future__ import annotations

import os
import sys
import json
import random
import traceback
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RNG = random.Random(1337)  # deterministic


def banner(title: str) -> None:
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def j(obj) -> str:
    return json.dumps(obj, default=str)


# ---------------------------------------------------------------------------
def gen_benign() -> dict:
    return {
        "source_ip": f"10.0.0.{RNG.randint(1, 50)}",
        "destination_port": RNG.choice([80, 443, 53, 22]),
        "protocol": RNG.choice(["TCP", "UDP"]),
        "bytes_sent": RNG.randint(100, 5000),
        "bytes_received": RNG.randint(100, 8000),
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=RNG.randint(0, 600)),
        "event_type": RNG.choice(["network_connection", "dns_query", "http_request", "authentication"]),
        "severity": RNG.choice(["info", "low", "medium"]),
    }


def gen_outlier() -> dict:
    return {
        "source_ip": f"203.0.113.{RNG.randint(1, 254)}",
        "destination_port": RNG.choice([31337, 4444, 6667, 65500]),
        "protocol": "ICMP",
        "bytes_sent": RNG.randint(5_000_000, 50_000_000),
        "bytes_received": RNG.randint(5_000_000, 50_000_000),
        "timestamp": datetime.now(timezone.utc).replace(hour=3, minute=RNG.randint(0, 59)),
        "event_type": "process_execution",
        "severity": "critical",
    }


def branch_of(result: dict) -> str:
    scores = result.get("scores", {})
    if "isolation_forest" in scores:
        return "isolation_forest (REAL ML)"
    if "heuristic" in scores:
        return "heuristic (FALLBACK)"
    return "unknown"


def section_ml() -> None:
    from core.engines.ml_anomaly_engine import ML_AVAILABLE, MLAnomalyEngine

    print("  ML_AVAILABLE:", ML_AVAILABLE)
    ml = MLAnomalyEngine()
    ml.load_models()  # loads shipped (hollow) model

    probe = gen_benign()
    before = ml.detect_anomalies(probe)
    print("  [shipped state] models_trained =", ml.models_trained,
          "| detect branch =", branch_of(before))

    # NON-DESTRUCTIVE: do not overwrite the shipped .joblib during a diagnostic.
    ml._save_models = lambda: None
    print("  (_save_models patched to no-op: on-disk model will NOT be modified)")

    # Populate feature history with benign events, then train explicitly.
    for _ in range(200):
        ml.detect_anomalies(gen_benign())
    print("  feature_history after 200 benign events:", len(ml.feature_history))

    ml.train_models()
    print("  [after real train] models_trained =", ml.models_trained,
          "| _models_ready() =", ml._models_ready())
    forest = ml.models.get("isolation_forest")
    if forest is not None:
        fitted = all(hasattr(forest, a) for a in ("estimators_", "offset_", "n_features_in_"))
        print("  isolation_forest fitted =", fitted,
              "| n_estimators =", getattr(forest, "n_estimators", None),
              "| n_features_in_ =", getattr(forest, "n_features_in_", None))
    print("  scaler n_features_in_ =", getattr(ml.scalers.get("standard"), "n_features_in_", None))

    # Confirm the REAL branch now runs, and show discrimination (reported honestly).
    fresh_benign = [gen_benign() for _ in range(10)]
    fresh_outliers = [gen_outlier() for _ in range(10)]
    b_res = [ml.detect_anomalies(e) for e in fresh_benign]
    o_res = [ml.detect_anomalies(e) for e in fresh_outliers]

    print("  post-train detect branch (sample):", branch_of(b_res[0]))
    b_flags = sum(1 for r in b_res if r.get("is_anomaly"))
    o_flags = sum(1 for r in o_res if r.get("is_anomaly"))
    print(f"  anomalies flagged -> benign: {b_flags}/10   outliers: {o_flags}/10")
    print("  sample benign  result:", j(b_res[0])[:260])
    print("  sample outlier result:", j(o_res[0])[:260])
    print("  ml stats:", j(ml.get_stats()))


# ---------------------------------------------------------------------------
def section_yara() -> None:
    from core.engines.signature_engine import YARA_AVAILABLE, SignatureEngine, YARARule

    print("  YARA_AVAILABLE:", YARA_AVAILABLE)
    sig = SignatureEngine()
    yara_rules = [rid for rid, r in sig.rules.items() if isinstance(r, YARARule)]
    print("  loaded YARA rules:", yara_rules)

    # SAFE synthetic payload: literal marker tokens the shipped rules key on.
    payload = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: malicious-domain.com\r\n"
        b"X-Forwarded-For: 192.168.1.100\r\n"
        b"User-Agent: labtest\r\n\r\n"
        b"cmd.exe /c whoami & powershell -enc QQBBAEEA\r\n"
    )
    hot_event = {
        "event_id": "yara_lab_001",
        "event_type": "network_connection",
        "source_ip": "10.0.0.9",
        "details": {"payload": payload},
    }
    matches = sig.scan_event(hot_event)
    print(f"  scan(payload with markers) -> {len(matches)} match(es):")
    for m in matches:
        print("    -", j({k: m.get(k) for k in ("rule_id", "rule_name", "confidence", "yara_matches", "severity")}))

    # Negative control: benign payload with no markers -> expect no YARA match.
    cold_event = {
        "event_id": "yara_lab_002",
        "event_type": "network_connection",
        "source_ip": "10.0.0.10",
        "details": {"payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"},
    }
    cold = sig.scan_event(cold_event)
    print(f"  scan(clean payload) -> {len(cold)} match(es)  (expected 0 from YARA)")
    print("  sig stats:", j(sig.get_stats()))


# ---------------------------------------------------------------------------
print("CYBER-EW FUSION CELL - ON-TARGET ENGINE VERIFICATION")
print("generated :", datetime.now(timezone.utc).isoformat())
print("python    :", sys.version.split()[0], "|", sys.executable)
print("cwd       :", os.getcwd())

banner("A) ML ANOMALY ENGINE - real IsolationForest path (trained in-memory, non-destructive)")
try:
    section_ml()
except Exception:
    print("  [SECTION ERROR]")
    traceback.print_exc()

banner("B) YARA SIGNATURE ENGINE - real match on safe synthetic payload")
try:
    section_yara()
except Exception:
    print("  [SECTION ERROR]")
    traceback.print_exc()

banner("ENGINE VERIFICATION COMPLETE")
print("Paste the full output back to promote/refute the ML and YARA layers.")
