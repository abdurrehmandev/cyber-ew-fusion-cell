#!/usr/bin/env python3
r"""
Cyber-EW Fusion Cell - ML train-crash diagnosis & fix verification (audit step 4)

Background (evidence already captured by audit/probe_engines.py):
  On this host, training an engine whose model was populated by load_models()
  CRASHED with:
      'ExtraTreeRegressor' object has no attribute 'monotonic_cst'
  Root cause: the shipped isolation_forest.joblib was pickled under sklearn <1.4;
  under the installed sklearn its stale tree template lacks `monotonic_cst`, so
  fitting the unpickled estimator throws. load_models() had overwritten the fresh
  in-memory estimator with that stale object, so (auto-)retraining could never
  succeed -> engine permanently stuck in heuristic mode.

This harness verifies the diagnosis AND the surgical fix in load_models():
  Scenario 1 - FRESH engine (never load_models): train must SUCCEED and detect
               must take the isolation_forest branch  => proves the ML CODE is
               sound (the defect was the stale artifact, not the algorithm).
  Scenario 2 - engine AFTER load_models() (now re-inits fresh estimators when the
               loaded artifact is unusable): train must SUCCEED  => proves the fix
               restores the retraining path that was previously poisoned.

NON-DESTRUCTIVE: _save_models is patched to a no-op in both scenarios, so the
shipped .joblib on disk is left exactly as-is (it remains the evidence for the
"hollow shipped model" finding). Uses only safe synthetic lab data.

Usage (from repo root, project venv):
    .\.venv\Scripts\python.exe audit\probe_ml_fix.py
"""
from __future__ import annotations

import sys
import json
import random
import traceback
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RNG = random.Random(1337)


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


def train_and_probe(ml, label: str) -> None:
    ml._save_models = lambda: None  # non-destructive: never touch shipped .joblib
    for _ in range(200):
        ml.detect_anomalies(gen_benign())
    ml.train_models()

    forest = ml.models.get("isolation_forest")
    fitted = forest is not None and all(
        hasattr(forest, a) for a in ("estimators_", "offset_", "n_features_in_")
    )
    print(f"  [{label}] train ok      : models_trained={ml.models_trained} "
          f"_models_ready={ml._models_ready()} forest_fitted={fitted} "
          f"n_features_in_={getattr(forest, 'n_features_in_', None)}")

    b = [ml.detect_anomalies(gen_benign()) for _ in range(20)]
    o = [ml.detect_anomalies(gen_outlier()) for _ in range(20)]
    print(f"  [{label}] detect branch : {branch_of(b[0])}")
    print(f"  [{label}] discrimination: benign anomalies {sum(r['is_anomaly'] for r in b)}/20"
          f"   outlier anomalies {sum(r['is_anomaly'] for r in o)}/20")
    print(f"  [{label}] sample outlier: {json.dumps(o[0], default=str)[:200]}")


import sklearn  # noqa: E402
from core.engines.ml_anomaly_engine import MLAnomalyEngine  # noqa: E402

print("CYBER-EW FUSION CELL - ML TRAIN-CRASH FIX VERIFICATION")
print("generated :", datetime.now(timezone.utc).isoformat())
print("python    :", sys.version.split()[0], "| scikit-learn", sklearn.__version__)

print("\n" + "=" * 74)
print("Scenario 1 - FRESH engine, NO load_models() (proves ML code is sound)")
print("=" * 74)
try:
    train_and_probe(MLAnomalyEngine(), "fresh")
except Exception:
    traceback.print_exc()

print("\n" + "=" * 74)
print("Scenario 2 - engine AFTER load_models() (proves the load_models fix)")
print("=" * 74)
try:
    ml2 = MLAnomalyEngine()
    ml2.load_models()  # fixed: re-inits fresh estimators if shipped artifact unusable
    print("  load_models() done; models_trained =", ml2.models_trained,
          "(expected False: shipped artifact hollow -> heuristic until trained)")
    train_and_probe(ml2, "post-load")
except Exception:
    traceback.print_exc()

print("\n" + "=" * 74)
print("FIX VERIFICATION COMPLETE")
print("=" * 74)
print("Expected: BOTH scenarios train_ok=True and branch=isolation_forest (REAL ML).")
print("Pre-fix, Scenario 2 crashed with the monotonic_cst AttributeError.")
