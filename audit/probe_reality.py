#!/usr/bin/env python3
r"""
Cyber-EW Fusion Cell - On-target Reality Probe  (audit harness, step 1)

Purpose: answer, with evidence, whether the detection layers that ran only in
FALLBACK inside the prior Linux sandbox are now genuinely active on this Windows
host - and whether the persisted ML models load AND remain compatible with the
current feature extractor.

Safety: this probe is read-only with respect to the running system. It does NOT
start any server, bind any socket, or send traffic. It instantiates the engines,
loads the on-disk ML models (joblib.load), lists signature rules, and calls the
platform's own collector_readiness() probe. Run only in the authorized project
environment.

Usage (from the repo root, with the project venv):
    .\.venv\Scripts\python.exe audit\probe_reality.py
"""
from __future__ import annotations

import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime, timezone

# This file lives in <repo_root>/audit/ - make the repo importable regardless of cwd.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def banner(title: str) -> None:
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def safe(fn) -> None:
    """Run a probe section; never let one failure abort the rest."""
    try:
        fn()
    except Exception:
        print("  [SECTION ERROR]")
        traceback.print_exc()


def j(obj) -> str:
    return json.dumps(obj, default=str)


print("CYBER-EW FUSION CELL - ON-TARGET REALITY PROBE")
print("generated  :", datetime.now(timezone.utc).isoformat())
print("python     :", sys.version.replace("\n", " "))
print("executable :", sys.executable)
print("cwd        :", os.getcwd())
print("repo root  :", ROOT)


# ---------------------------------------------------------------------------
def section_versions() -> None:
    from importlib import metadata
    dists = [
        "numpy", "pandas", "scipy", "scikit-learn", "joblib",
        "yara-python", "scapy", "pyshark",
        "fastapi", "uvicorn", "starlette", "pydantic",
        "streamlit", "requests", "PyYAML", "python-dateutil",
    ]
    for dist in dists:
        try:
            print(f"  {dist:16s} {metadata.version(dist)}")
        except Exception as exc:
            print(f"  {dist:16s} NOT INSTALLED ({exc.__class__.__name__})")


banner("1) PACKAGE VERSIONS (on-target venv)")
safe(section_versions)


# ---------------------------------------------------------------------------
def section_config() -> None:
    from config.settings import CONFIG
    dd = Path(CONFIG.data_dir)
    print("  CONFIG.data_dir :", dd, "(exists)" if dd.exists() else "(MISSING)")
    for sub in ("signatures", "ml_models", "inputs", "inputs/live", "inputs/logs"):
        p = dd / sub
        print(f"    {sub:14s}:", "exists" if p.exists() else "MISSING")


banner("2) CONFIG / DATA DIRECTORIES")
safe(section_config)


# ---------------------------------------------------------------------------
def section_ml() -> None:
    from core.engines.ml_anomaly_engine import ML_AVAILABLE, MLAnomalyEngine
    from config.settings import CONFIG

    print("  ML_AVAILABLE (numpy+sklearn+joblib import):", ML_AVAILABLE)
    ml = MLAnomalyEngine()
    print("  init stats :", j(ml.get_stats()))

    # Feature-vector shape from the CURRENT extractor (dict input is accepted).
    sample = {
        "source_ip": "10.0.0.42", "destination_port": 443, "protocol": "TCP",
        "bytes_sent": 1200, "bytes_received": 3400,
        "timestamp": datetime.now(timezone.utc),
        "event_type": "network_connection", "severity": "high",
    }
    feats = ml.extract_features(sample)
    print(f"  extract_features -> {len(feats)} features: {list(feats.keys())}")

    mdir = Path(CONFIG.data_dir) / "ml_models"
    print("  model files:", sorted(p.name for p in mdir.glob('*')) if mdir.exists() else "(no dir)")

    # Exercise the persisted-model load path (joblib.load deserialization sink).
    ml.load_models()
    print("  after load :", j(ml.get_stats()))
    print("  _models_ready():", ml._models_ready())

    forest = ml.models.get("isolation_forest")
    if forest is not None:
        fitted = all(hasattr(forest, a) for a in ("estimators_", "offset_", "n_features_in_"))
        print("  isolation_forest fitted:", fitted,
              "| n_features_in_:", getattr(forest, "n_features_in_", None))
    scaler = ml.scalers.get("standard")
    print("  scaler n_features_in_ :", getattr(scaler, "n_features_in_", None),
          "  (compare to feature count above -> mismatch = persisted model incompatible)")

    # Does a real detection use the model branch or fall back to the heuristic?
    res = ml.detect_anomalies(sample)
    scores = res.get("scores", {})
    if "isolation_forest" in scores:
        branch = "isolation_forest (REAL ML)"
    elif "heuristic" in scores:
        branch = "heuristic (FALLBACK)"
    else:
        branch = "unknown (model path raised - see debug)"
    print("  detect_anomalies -> branch:", branch)
    print("  detect_anomalies -> result:", j(res)[:400])


banner("3) ML ANOMALY ENGINE - reality & persisted-model compatibility")
safe(section_ml)


# ---------------------------------------------------------------------------
def section_signatures() -> None:
    from core.engines.signature_engine import YARA_AVAILABLE, SignatureEngine, YARARule

    print("  YARA_AVAILABLE (import yara):", YARA_AVAILABLE)
    sig = SignatureEngine()
    print("  stats :", j(sig.get_stats()))
    print("  rules loaded:")
    for rid, r in sig.rules.items():
        is_yara = isinstance(r, YARARule)
        kind = "YARA" if is_yara else "signature"
        compiled = "compiled" if (is_yara and getattr(r, "yara_rule", None) is not None) else ""
        print(f"    - {rid:30s} [{kind:9s}] {compiled:9s} sev={r.severity} enabled={r.enabled}")


banner("4) SIGNATURE / YARA ENGINE - reality & loaded rules")
safe(section_signatures)


# ---------------------------------------------------------------------------
def section_collectors() -> None:
    from core.collectors.manager import collector_readiness
    print(json.dumps(collector_readiness(), indent=2, default=str))


banner("5) COLLECTOR READINESS (windows_eventlog / sysmon / pcap_live)")
safe(section_collectors)


banner("PROBE COMPLETE")
print("Next: paste this full output back so the audit can promote/refute each layer.")
