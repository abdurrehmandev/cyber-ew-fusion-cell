#!/usr/bin/env python3
r"""
Cyber-EW Fusion Cell - On-target API Verification  (audit harness, step 3)

Exercises the REAL FastAPI app in-process via TestClient (NO socket is bound,
no external target) and proves the API-key security posture with evidence.

What it proves:
  1) Route inventory: enumerate every registered route and programmatically
     detect which ones carry the require_api_key dependency (expect exactly 4
     gated POST routes: /lake/snapshot, /playbooks/run, /cases, /iocs).
  2) GET sweep: every read-only GET route returns a healthy status in-process.
  3) Auth matrix (the security-relevant part). require_api_key only enforces
     when CYBER_EW_API_KEY is SET -> auth is OPT-IN:
       Phase A (env UNSET): gated POST routes with NO key are NOT rejected
                            (422 validation, not 401) -> auth is INERT by default.
       Phase B (env SET)  : gated POST routes with NO/WRONG key -> 401;
                            with CORRECT key -> passes the gate (422 validation).

NON-DESTRUCTIVE: mutating routes are probed with intentionally-invalid bodies so
a request that passes the auth gate fails at body validation (422) instead of
writing real cases/IOCs. /lake/snapshot (no body, would write) is only tested for
the no-key -> 401 case (rejected BEFORE the handler runs), so nothing is written.

Usage (from repo root, project venv):
    .\.venv\Scripts\python.exe audit\probe_api.py
"""
from __future__ import annotations

import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

KEY_ENV = "CYBER_EW_API_KEY"
LAB_KEY = "lab-audit-key-1337"


def banner(title: str) -> None:
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def snippet(resp, n: int = 90) -> str:
    try:
        body = json.dumps(resp.json(), default=str)
    except Exception:
        body = resp.text
    body = body.replace("\n", " ")
    return body[:n]


# Make the auth env deterministic: start with it UNSET regardless of shell.
os.environ.pop(KEY_ENV, None)

print("CYBER-EW FUSION CELL - ON-TARGET API VERIFICATION")
print("generated :", datetime.now(timezone.utc).isoformat())
print("python    :", sys.version.split()[0], "|", sys.executable)

# --- import the real app; guard TestClient (needs httpx) --------------------
try:
    from fastapi.testclient import TestClient
except Exception as exc:  # httpx missing, etc.
    print("\n[FATAL] Cannot import fastapi.testclient TestClient:", repr(exc))
    print("        TestClient needs 'httpx'. Install once, then re-run:")
    print("        .\\.venv\\Scripts\\python.exe -m pip install httpx")
    sys.exit(2)

from interfaces.api import app, require_api_key  # noqa: E402

client = TestClient(app)


# ---------------------------------------------------------------------------
def section_inventory():
    from fastapi.routing import APIRoute

    gated, ungated = [], []
    for r in app.routes:
        if not isinstance(r, APIRoute):
            continue
        methods = sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))
        dep = getattr(r, "dependant", None)
        is_gated = bool(dep) and any(d.call is require_api_key for d in dep.dependencies)
        (gated if is_gated else ungated).append((methods, r.path))

    print(f"  total API routes: {len(gated) + len(ungated)}")
    print(f"  API-key GATED routes ({len(gated)}):")
    for methods, path in sorted(gated, key=lambda x: x[1]):
        print(f"    - {'/'.join(methods):5s} {path}")
    print(f"  ungated routes ({len(ungated)}):")
    for methods, path in sorted(ungated, key=lambda x: x[1]):
        print(f"    - {'/'.join(methods):5s} {path}")
    return [p for _, p in gated]


# ---------------------------------------------------------------------------
def section_get_sweep():
    get_paths = [
        "/health", "/readiness", "/metrics", "/capabilities", "/connectors",
        "/lake/stats", "/playbooks", "/playbooks/runs", "/alerts",
        "/attack/timeline", "/cases", "/iocs", "/audit", "/export/bundle",
        "/openapi.json",
    ]
    for p in get_paths:
        try:
            resp = client.get(p)
            print(f"  GET {p:22s} -> {resp.status_code}   {snippet(resp)}")
        except Exception as exc:
            print(f"  GET {p:22s} -> EXC {exc!r}")


# ---------------------------------------------------------------------------
# Non-destructive auth probes: invalid/empty bodies so a request that PASSES the
# gate fails at validation (422) rather than writing anything.
BODY_ROUTES = ["/cases", "/iocs", "/playbooks/run"]  # gated POST w/ required body
NOBODY_ROUTES = ["/lake/snapshot"]                    # gated POST, no body (would write)


def section_auth_optout():
    print(f"  {KEY_ENV} is UNSET -> require_api_key should be INERT")
    for p in BODY_ROUTES:
        resp = client.post(p, json={})  # empty body, no key
        verdict = "NOT blocked (auth inert)" if resp.status_code != 401 else "BLOCKED (401)"
        print(f"  POST {p:16s} no key -> {resp.status_code}  [{verdict}]  {snippet(resp, 60)}")
    print("  (skipping /lake/snapshot handler-exec here to avoid a real lake write)")


def section_auth_enforced():
    os.environ[KEY_ENV] = LAB_KEY
    print(f"  {KEY_ENV} is SET -> require_api_key should ENFORCE")
    try:
        # No key -> expect 401 on ALL 4 gated routes (rejected before handler).
        for p in BODY_ROUTES + NOBODY_ROUTES:
            resp = client.post(p, json={})
            verdict = "ENFORCED (401)" if resp.status_code == 401 else f"NOT enforced ({resp.status_code})"
            print(f"  POST {p:16s} no key      -> {resp.status_code}  [{verdict}]")
        # Wrong key -> expect 401.
        for p in BODY_ROUTES:
            resp = client.post(p, json={}, headers={"X-API-Key": "wrong"})
            verdict = "ENFORCED (401)" if resp.status_code == 401 else f"NOT enforced ({resp.status_code})"
            print(f"  POST {p:16s} wrong key   -> {resp.status_code}  [{verdict}]")
        # Correct key -> passes gate, then 422 validation (empty body). NOT 401.
        for p in BODY_ROUTES:
            resp = client.post(p, json={}, headers={"X-API-Key": LAB_KEY})
            verdict = "PASSED gate" if resp.status_code != 401 else "still 401 (BUG)"
            print(f"  POST {p:16s} correct key -> {resp.status_code}  [{verdict}]  {snippet(resp, 60)}")
        print("  (/lake/snapshot with correct key NOT executed: it would write to the lake)")
    finally:
        os.environ.pop(KEY_ENV, None)


def section_ungated_post():
    # /hunt/query is a POST but intentionally ungated (read-only query).
    resp = client.post("/hunt/query", json={"query": "alerts | take 5", "limit": 5})
    print(f"  POST /hunt/query (no key) -> {resp.status_code}  {snippet(resp, 120)}")


# ---------------------------------------------------------------------------
for title, fn in [
    ("1) ROUTE INVENTORY + GATED-ROUTE DETECTION", section_inventory),
    ("2) GET SWEEP (read-only routes, in-process)", section_get_sweep),
    ("3a) AUTH OPT-OUT  (CYBER_EW_API_KEY unset)", section_auth_optout),
    ("3b) AUTH ENFORCED (CYBER_EW_API_KEY set)", section_auth_enforced),
    ("4) UNGATED POST /hunt/query", section_ungated_post),
]:
    banner(title)
    try:
        fn()
    except Exception:
        print("  [SECTION ERROR]")
        traceback.print_exc()

banner("API VERIFICATION COMPLETE")
print("Paste the full output back to promote/refute the API + auth layer.")
