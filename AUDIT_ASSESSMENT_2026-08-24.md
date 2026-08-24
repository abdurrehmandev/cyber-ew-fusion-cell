# Cyber-EW Fusion Cell — Engineering Assessment & Roadmap

**Audit date:** 2026-08-24
**Auditor role:** Principal SIEM Architect / Detection Engineer / DevSecOps / QA
**Subject:** `C:\Users\rehman\OneDrive\Documents\cyber-ew-fusion-cell` (the complete, authoritative copy)
**Method:** Hands-on. Every claim below is backed by executed code and captured output, following the standard **Evidence → Test → Diagnosis → Fix → Verification → Measurement**. Nothing is marked "done" because a file, class, endpoint, or README exists — only because it ran and was verified.

> **Scope & safety note.** All execution was performed against the project's own code in an isolated sandbox using synthetic/lab data only. No real malicious infrastructure was contacted (outbound threat-feed calls were blocked by the sandbox proxy and handled gracefully). Active testing was confined to the authorized project environment.

> **Environment caveat that shapes several findings.** The audit sandbox has **no PyPI access** (proxy returns 403). Only `numpy 2.2.6`, `pandas 2.3.3`, `python-dateutil 2.9`, `PyYAML 6.0.3`, and `requests 2.34.2` are installed. `scikit-learn`, `fastapi`, `yara-python`, `scapy`, `pyshark`, `stix2`, `streamlit`, `uvicorn`, and `pydantic` are **absent**, so those layers ran only in their fallback paths and could not be exercised natively here. This is an **environment limitation, not a code defect**, and is called out wherever it affects a result. The project's bundled virtualenv is Windows-only and could not be reused in the Linux sandbox.

---

## 1. Executive Summary (the verified bottom line)

Cyber-EW Fusion Cell is a **genuinely functional, multi-threaded SIEM/analytics prototype** — not a hollow scaffold. It starts cleanly, runs a real threaded ingestion→normalize→correlate→behavior→(threat-intel/ML/signature)→score→alert pipeline, produces **real, discriminating threat scores** (malicious ≈ 0.97/critical vs benign ≈ 0.31), and degrades gracefully when optional dependencies (ML, YARA, network, Windows APIs) are missing.

It is **also less finished than a first glance suggests**. The convenience `--test` path prints **hardcoded** threat-score/behavior/correlation numbers rather than computed ones; correlation is **O(n²)** with unbounded state; the behavioral-baseline anomaly path is inert; SOAR is a dry-run stub; and there are counter/config inconsistencies. None of these are fatal, but they mean the honest label is **"functional alpha,"** not "production SIEM."

During this audit I diagnosed and **fixed two real defects** (ML fallback state leak; a timezone bug that silently disabled recency decay for every event), each verified by re-running the test suite and targeted probes. The smoke suite moved from **12/14 → 13/14** (the one remaining failure is purely the missing `fastapi` in the sandbox).

**Phase: 2 of 7 (Functional Alpha / Integrated Prototype).** **Overall maturity ≈ 38%** toward a production-grade on-prem SIEM. The strongest areas are the ingestion/normalization/scoring core and graceful degradation; the weakest are scale/performance, automation (SOAR), UEBA depth, and operational hardening (RBAC, multi-tenancy, packaging).

---

## 2. Audit Methodology & Evidence Standard

| Principle | How it was applied |
|---|---|
| Discover actual implementation | Read source directly (no reliance on docs/README claims). |
| Establish baseline | Enumerated interpreter + installed packages; identified blocked deps. |
| Attempt clean startup | Ran `main.py --test` and a real threaded pipeline start/stop. |
| Verify end-to-end | Fed events through the real 4-thread pipeline; inspected drained queues and persisted alerts. |
| Diagnose → Fix → Re-verify | Reproduced each defect's mechanism, applied surgical fixes, re-ran tests. |
| Measure | Benchmarked scoring and end-to-end throughput with real timers. |
| Don't fabricate defects | When a probe erred due to my malformed test data, I traced the real producer/consumer contract and **retracted** the phantom bug. |

**Key evidence artifacts (reproducible commands):**

- `python3 main.py --test` → exit 0.
- Threaded run: `CyberEWPipeline().start(); sleep(6); get_stats(); stop()` → 289 events, clean drain, 3 real alerts.
- Smoke suite executed via a pytest-free runner (pytest itself is not installed): 13/14 pass.
- Scoring probes for recency decay, multi-source scoring, and ML fallback state.

---

## 3. Verified Current State (what actually runs)

**Startup — VERIFIED.** `main.py --test` returns exit code 0. All engines initialize; optional-dependency warnings (ML, YARA) are logged and handled, not fatal.

**Real threaded pipeline — VERIFIED.** Starting the pipeline spins up **4 daemon worker threads** over **3 bounded queues**. In a 6-second run against the simulated sources:

```
events_processed: 289
processing_rate : 48 ev/s        (source-limited, not processor-limited)
queue_status    : all queues drained to 0 (no backlog)
recent_alerts   : 3 real, computed alerts, e.g.
   - authentication | Source 192.168.1.66 | Threat Level: HIGH | Confidence: 70%
CLEAN_STOP: True
```

These alerts are **computed by the real scoring engine** in the worker path (not canned), confirming the end-to-end pipeline genuinely detects and alerts.

**Graceful degradation — VERIFIED.** In the same run the system survived, without crashing: ThreatFox feed `403` (blocked network), syslog UDP/514 bind `Permission denied`, ML dependencies absent (→ heuristics), YARA absent (→ fallback). This is a real strength.

**Detection discrimination — VERIFIED.** A multi-source malicious event (threat-intel + signature + ML-anomaly) scores **0.971 → CRITICAL** (confidence 0.8) with a fully populated `details` breakdown; a benign event scores ≈ **0.31**. The scoring is real and separates signal from noise.

**Code scale (real project, measured):**

| Area | Files | LOC |
|---|---:|---:|
| `core/` (engines, models, pipeline) | 40 | 12,317 |
| `utils/` | 10 | 1,968 |
| `interfaces/` (API, dashboard) | 8 | 1,607 |
| `config/` | 9 | 604 |
| `storage/` | 9 | 618 |
| repo root `*.py` | 77 | 11,276 |

Order of magnitude ≈ **28k+ LOC** of first-party Python. (The 77 root-level `.py` files and a `config/settings - Copy.py` duplicate indicate housekeeping debt — see §6.)

---

## 4. Environment & Dependency Baseline

| Component | Declared (`requirements.txt`) | Available in audit sandbox | Effect on audit |
|---|---|---|---|
| Python | — | 3.10.12 | ✅ |
| numpy / pandas / dateutil / PyYAML / requests | ✓ | ✓ | Core paths fully exercised |
| scikit-learn 1.8.0 (pinned) | ✓ | ✗ (PyPI blocked) | ML ran in **heuristic fallback** only |
| fastapi / uvicorn / pydantic | ✓ | ✗ | API import test fails in sandbox only |
| yara-python | ✓ | ✗ | Signature engine used regex + fallback |
| scapy / pyshark | ✓ | ✗ | PCAP source ran simulated |
| stix2 / taxii2-client | ✓ | ✗ | STIX output is hand-rolled JSON regardless |
| streamlit / pywebview | ✓ | ✗ | Dashboard not launchable here |
| pywin32 | ✓ (win32 only) | n/a | Windows-only paths not testable on Linux |

**Takeaway:** the code's graceful-degradation design let the **core** be fully audited despite a locked-down environment. Layers requiring blocked wheels (ML models, FastAPI service, YARA, live PCAP) must be validated on the intended Windows target with the bundled venv before any production claim.

---

## 5. Broken Components — Diagnosed, Fixed, and Re-verified

Two real defects were found, reproduced at the mechanism level, fixed surgically (commented in-code), and re-verified.

### 5.1 ML fallback state leak — FIXED ✅
- **File:** `core/engines/ml_anomaly_engine.py`, `detect_anomalies`.
- **Mechanism:** when `ML_AVAILABLE` is `False`, the method returned the heuristic result **before** the `models_trained` reset logic (lines ~261-262), so a stale `models_trained=True` could persist while no fitted model existed. The smoke test `test_ml_unfitted_models_fall_back_to_heuristics` asserted this must be `False`.
- **Fix:** set `self.models_trained = False` inside the `if not ML_AVAILABLE:` branch (heuristic mode must never advertise trained models).
- **Verification:** probe now shows `models_trained after call: False`, scores key `['heuristic']`; the previously-failing smoke test **passes**.

### 5.2 Recency decay silently disabled by naive/aware datetime bug — FIXED ✅
- **File:** `core/engines/scoring_engine.py`, `_calculate_recency_score`.
- **Mechanism:** line computed `datetime.utcnow()` (**naive**) minus a **timezone-aware** event timestamp → `TypeError: can't subtract offset-naive and offset-aware datetimes` → swallowed by the method's `except Exception: return 1.0`. **Every** real event (all carry tz-aware UTC timestamps) therefore received recency **1.0**, and the entire decay ladder (1.0/0.8/0.5/0.2) was dead code.
- **Reproduced:** `(datetime.utcnow() - isoparse("…Z"))` raises the exact `TypeError`.
- **Fix:** use the project's own `datetime_now_utc()` and `ensure_utc(timestamp)` (added import; consistent with `main.py`). No new dependency.
- **Verification:** decay now returns **1.0 / 0.8 / 0.5 / 0.2** for events aged <1h / 6h / 48h / 10d, and end-to-end scoring still yields sane values (0.0–1.0).

### 5.3 Retracted (not a defect)
A probe initially appeared to show a crash in `_calculate_threat_intel_score` (`'str' object has no attribute 'get'`). Tracing the real contract, `threat_intel_engine.match_event` returns items with `"ioc": asdict(ioc)` (a **dict**), which the scorer consumes correctly. **The error was my malformed test data, not a code bug** — recorded here for honesty.

**Net test-suite movement:** **12/14 → 13/14** passing. The remaining failure (`test_api_imports`) is solely `ModuleNotFoundError: fastapi` in the sandbox and would pass on the target with the bundled venv.

---

## 6. Remaining Confirmed Defects (not fixed — deliberately, to keep edits minimal)

| # | Defect | Evidence | Severity | Why not auto-fixed |
|---|---|---|---|---|
| D1 | **`test_pipeline()` returns hardcoded results.** Threat scores, behavior patterns, and correlation clusters in `--test` output are literals (`pipeline.py:523-529`), though the method *does* run the real detection engines. | Source lines 517-531 | High (integrity/optics) | Changing test-mode output is a design choice; flagged for owner decision. |
| D2 | **Correlation is O(n²) with unbounded state.** Throughput degrades as correlation state grows. | End-to-end rate fell from ~4,945 → ~532 ev/s as state accumulated | High (scale) | Needs a real windowing/eviction redesign, not a one-liner. |
| D3 | **`alerts_generated` counter divergence.** Stats reported `0` while `get_recent_alerts` returned 3 real alerts. | Threaded run output | Medium | Small fix but needs owner to confirm intended counter semantics. |
| D4 | **Behavioral-baseline anomaly path inert.** Baseline deviation does not contribute in practice. | Prior code trace | Medium | Requires baseline-population design. |
| D5 | **SOAR / response is a dry-run stub.** No real actions taken. | Code trace | Medium | By design for now; must be explicit in maturity claims. |
| D6 | **Config weight-key drift.** `config/settings.py` defines weights `severity`/`confidence`/`behavior`, but the engine emits `event_severity`/`behavior_analysis` and no `confidence` component — so those configured weights are **inert** and the intended weighting silently reverts to engine defaults. | `settings.py:69-73` vs `scoring_engine.py:113-158` | Medium | Fixing requires knowing intended weighting. |
| D7 | **Housekeeping debt.** `config/settings - Copy.py` duplicate; ~77 `.py` files in repo root. | Directory scan | Low | Cosmetic but erodes reviewer trust. |

---

## 7. Development Phase Determination (0–7)

Using a standard lifecycle (0 concept · 1 prototype · 2 functional alpha · 3 beta/feature-complete · 4 release candidate/hardened · 5 GA/production · 6 scaled · 7 mature-maintenance):

**Verdict: Phase 2 of 7 — Functional Alpha (Integrated Prototype), with a few Phase-3 traits.**

**Justification (evidence-based):**
- ✅ *Above Phase 1:* it is not a skeleton — the full pipeline runs end-to-end and produces real, discriminating detections with graceful degradation. Multiple real subsystems (ingest, normalize, score, threat-intel, signatures, storage, API surface) are integrated.
- ⛔ *Not yet Phase 3:* test-mode emits canned values (D1); a core algorithm is O(n²) (D2); UEBA baseline is inert (D4); SOAR is a stub (D5); the ML/YARA/API layers are unverified on-target; no performance or security hardening; packaging is single-platform.

---

## 8. Maturity Assessment (by dimension)

| Dimension | Maturity | Basis |
|---|---:|---|
| Core pipeline & orchestration | **70%** | Real 4-thread queue pipeline, clean start/stop, drains correctly |
| Ingestion & normalization | **60%** | File/JSON/syslog real; PCAP simulated; parsers for Suricata/Zeek/Sysmon verified |
| Scoring & alerting | **65%** | Real multi-source weighted scoring, good discrimination; recency now fixed |
| Threat intelligence | **55%** | Real feed clients + local IOC; offline fallback; live feeds unverified (blocked) |
| Signature detection | **55%** | Real regex engine (4 rules loaded); YARA layer unverified |
| ML / UEBA | **30%** | Heuristic fallback solid; sklearn path & behavioral baseline unverified/inert |
| Correlation | **35%** | Works but O(n²)/unbounded |
| SOAR / response | **15%** | Dry-run stub |
| API / interfaces | **40%** | 20 FastAPI endpoints, opt-in auth; not runnable in sandbox; dashboard untested |
| Storage / case mgmt | **55%** | AlertStore/CaseStore/IOCStore/SecurityLake/AuditLog present and unit-tested |
| Security of the platform | **45%** | Real crypto utils; but opt-in auth, MD5 dedup, joblib deserialization |
| Testing / QA | **40%** | 14 smoke tests (13 pass); no integration/load/security test tiers |
| Performance & scale | **25%** | Single-process; O(n²) correlation; no back-pressure tuning |
| Packaging & ops | **20%** | Windows-only venv; no cross-platform/container story |
| **Overall (weighted)** | **≈ 38%** | Functional alpha |

---

## 9. Capability Matrix (verified vs. claimed)

Legend: **✅ Verified running** · **◑ Runs in fallback / partially** · **◒ Present, unverified on-target** · **✗ Stub/absent**

| Capability | Status | Evidence / Note |
|---|:--:|---|
| CLI entry & modes (`run/test/stats/console`) | ✅ | `main.py --test` exit 0; modes present |
| Threaded pipeline (4 workers, 3 queues) | ✅ | 289 ev/6s, queues drain, clean stop |
| Normalization + sensor parsers (Suricata/Zeek/Sysmon/WinEvt) | ✅ | Smoke tests pass |
| Real weighted scoring (multi-source) | ✅ | 0.971/critical vs 0.31 benign |
| Recency decay | ✅ | Fixed & verified (1.0/0.8/0.5/0.2) |
| Signature engine (regex) | ✅ | 4 rules loaded at startup |
| Threat-intel local IOC | ✅ | Offline match path works |
| Threat-intel live feeds (ThreatFox/OTX) | ◒ | Code real; network blocked in sandbox |
| ML anomaly (heuristic) | ◑ | Fallback verified |
| ML anomaly (IsolationForest/DBSCAN) | ◒ | sklearn absent here; joblib artifacts present |
| YARA layer | ◑ | Fallback verified; YARA absent |
| Correlation clustering | ◑ | Works but O(n²)/unbounded (D2) |
| Behavioral UEBA baseline | ✗ | Inert (D4) |
| Output: JSON/CSV/CEF/CONSOLE | ✅ | Real formatters |
| Output: STIX | ◑ | Hand-rolled JSON, not `stix2` |
| Output: SYSLOG | ◒ | Present; bind blocked in sandbox |
| Storage: Alert/Case/IOC/AuditLog/SecurityLake | ✅ | Unit-tested |
| Hunting query engine | ◒ | Present (`HuntingQueryEngine`); depth unverified |
| FastAPI service (20 endpoints) | ◒ | fastapi absent here; import fails in sandbox only |
| Dashboard (streamlit) | ◒ | Not launchable in sandbox |
| SOAR / automated response | ✗ | Dry-run stub (D5) |
| Windows service integration | ◒ | Windows-only; not testable on Linux |

---

## 10. Microsoft Sentinel Gap Analysis

Benchmarked against Microsoft Sentinel as the reference cloud-native SIEM.
Legend: 🟢 comparable / production-viable · 🟡 present but basic/partial · 🟠 rudimentary/stub · 🔴 missing but scaffolded · ⚫ absent entirely

| Sentinel capability | Cyber-EW | Rating | Gap commentary |
|---|---|:--:|---|
| Data connectors (breadth) | syslog/file/JSON/PCAP-sim | 🟡 | A handful of sources vs Sentinel's hundreds; extensible but narrow |
| Schema normalization (ASIM) | Custom normalizer + parsers | 🟡 | Real normalization; no standardized cross-source schema |
| Analytics/correlation rules | Regex signatures + basic correlation | 🟡 | Works; O(n²) limits scale; no rule-authoring UX |
| Scheduled/near-real-time analytics | Continuous threaded workers | 🟡 | Real-time-ish; no scheduling framework |
| UEBA / ML behavioral analytics | Heuristic + optional IsolationForest | 🟠 | Baseline inert; no entity behavior profiling at Sentinel depth |
| Threat intelligence integration | ThreatFox/OTX/local IOC | 🟡 | Solid design; live feeds unverified here |
| Hunting (KQL-class) | `HuntingQueryEngine` | 🟡 | Present; expressiveness far below KQL |
| Incident/case management | Case/IOC stores | 🟡 | Basic persistence; no investigation graph/timeline UI |
| SOAR / playbooks (Logic Apps) | Dry-run stub | 🟠 | No real automated response |
| Workbooks / dashboards | Streamlit dashboard | 🟠 | Untested here; not comparable to Workbooks |
| Notebooks / advanced hunting | — | 🔴 | Not present; scaffolding could host it |
| Multi-workspace / multi-tenancy | Single instance | 🔴 | Not designed for tenancy |
| RBAC / identity integration | Opt-in API key only | 🔴 | No role model; no AAD/SSO |
| Scale & cloud-native elasticity | Single-process threaded | 🔴 | No horizontal scale; bounded by one host |
| Data lake / long-term retention | `SecurityLake` module | 🟡 | Present; retention/tiering unproven |
| Compliance & audit logging | `AuditLog` | 🟡 | Present; not mapped to frameworks |
| Automated content/detection updates | Local rules/IOCs | 🟠 | Manual; no managed content pipeline |

**Summary:** Cyber-EW covers the **detection-engineering fundamentals** at 🟡 level in several areas — a credible on-prem/air-gapped analytics core — but is 🟠/🔴 on the **enterprise-platform** dimensions (SOAR, RBAC/tenancy, elastic scale, managed content) that define Sentinel. It is best positioned as a **lightweight, offline-capable detection engine**, not a Sentinel replacement.

---

## 11. Security Posture of the Platform Itself

**Clean on the high-risk anti-patterns.** Targeted review found **no** `eval`/`exec`, no `subprocess` shelling, no unsafe `yaml.load`, no `verify=False`, and no hardcoded secrets in the core modules.

**Real security utilities.** `utils/security.py` implements PBKDF2-HMAC-SHA256 (100k iterations) password hashing, constant-time comparison (`hmac.compare_digest`), HMAC signing/verification, path-traversal validation, `secrets`-based API-key generation, and sensitive-data masking — genuine, not placeholder.

| Finding | Location | Severity | Recommendation |
|---|---|:--:|---|
| Unauthenticated GET endpoints; auth is **opt-in** (only if `CYBER_EW_API_KEY` set) and only on 4 POST routes | `interfaces/api.py:104-106` | High | Make auth mandatory; protect read routes; add rate limiting |
| `joblib.load` of model artifacts (deserialization sink) | `ml_anomaly_engine.py:467,472` | Medium | Load only from signed/trusted paths; integrity-check artifacts |
| MD5 used for dedup keys | `alert_store.py:113`, `dashboard.py:367` | Low | Not a crypto use, but switch to SHA-256 to avoid audit flags |
| Syslog source binds `0.0.0.0` by default | `ingest_engine.py:128` | Medium | Default to loopback; require explicit bind config |
| No RBAC / tenancy / session model | platform-wide | High (for multi-user) | Add role model before any shared deployment |

**Net:** the platform is **reasonably safe for single-operator, on-prem/air-gapped use** (its stated deployment target), but **not hardened for multi-user or internet-exposed** operation.

---

## 12. Performance Baseline (measured)

| Metric | Measurement | Conditions |
|---|---:|---|
| Scoring stage throughput (isolated) | **≈ 57,000 events/s** | 5,000 events in 0.09s, no correlation state |
| End-to-end throughput (fresh state) | up to **≈ 4,945 events/s** | early in run, small correlation state |
| End-to-end throughput (accumulated state) | down to **≈ 532 events/s** | after correlation state grows — **O(n²) evidence** |
| Live threaded run (simulated sources) | **48 events/s / 289 in 6s** | source-emission-limited, not CPU-limited; queues never backlogged |
| Startup time | sub-second to first event | all engines init < 1s |

**Interpretation:** the per-event compute is cheap (scoring alone ~57k/s); the **binding constraint is the correlation engine's quadratic growth** (D2). For sustained high-EPS ingestion, correlation must move to bounded sliding windows with eviction. Until then, publish a **safe sustained-EPS ceiling** and document the degradation curve.

---

## 13. Regression Test Coverage

- **Suite:** `tests/test_smoke.py`, 14 tests covering normalization, ingest field preservation, Suricata/Zeek/Sysmon parsers, MITRE mapping, deployment profiles, Windows event XML, collector readiness, behavior scoring, ML fallback, alert dedup, case/IOC persistence, API import, YARA-without-payload.
- **Result this audit:** **13 pass / 1 fail**. The single failure is `test_api_imports` → `fastapi` not installed in the sandbox (**environment**, not code). All three fixture-based tests pass when given a temp dir.
- **Gaps:** no integration test for the *real threaded* pipeline; no load/soak test; no security/abuse test tier; test-mode assertions don't guard against the canned-output issue (D1). Recommended additions are in the backlog (§14).

---

## 14. Top-20 Prioritized Remediation Backlog

Priority = impact × (integrity/scale risk). P1 = highest.

| # | Item | Type | Rationale |
|---:|---|---|---|
| 1 | Replace hardcoded `test_pipeline()` results with computed values (D1) | Integrity | Restores trust; test mode should reflect reality |
| 2 | Redesign correlation to bounded sliding windows + eviction (D2) | Scale | Removes the O(n²) ceiling |
| 3 | Make API auth mandatory; protect GET routes; add rate limiting | Security | Closes the largest exposure |
| 4 | Add an **integration test** that runs the real threaded pipeline and asserts real alerts | QA | Guards the true happy path |
| 5 | Fix `alerts_generated` counter to match the alert store (D3) | Correctness | Accurate ops metrics |
| 6 | Implement behavioral baseline so UEBA contributes (D4) | Detection | Unlocks a claimed capability |
| 7 | Verify ML path on-target with sklearn 1.8.0 + signed model artifacts | ML/Sec | Confirms the ML tier; mitigates joblib risk |
| 8 | Resolve config weight-key drift (D6); add a startup weight-validation check | Correctness | Configured weights should take effect |
| 9 | Integrity-check/sign model artifacts before `joblib.load` | Security | Deserialization hardening |
| 10 | Implement real SOAR actions (or clearly label as roadmap) (D5) | Feature/Integrity | Aligns claims with behavior |
| 11 | Add RBAC + session/identity model | Security | Prerequisite for multi-user |
| 12 | Publish sustained-EPS ceiling + back-pressure policy | Ops | Sets safe operating envelope |
| 13 | Verify FastAPI service + dashboard on-target; add smoke test that starts the API | QA | Confirms interfaces tier |
| 14 | Default syslog bind to loopback; require explicit exposure | Security | Reduce attack surface |
| 15 | Replace MD5 dedup with SHA-256 | Security | Removes audit flag |
| 16 | Repo hygiene: remove `settings - Copy.py`; move root scripts into packages | Maintainability | Reviewer trust |
| 17 | Add load/soak test harness with the degradation curve | Perf/QA | Quantify scale limits |
| 18 | Real STIX via `stix2` (or document the JSON shim) | Interop | Standards compliance |
| 19 | Cross-platform packaging (container / Linux venv) | Ops | Portability, reproducible audits |
| 20 | Expand hunting query expressiveness + document query language | Feature | Narrows Sentinel gap |

---

## 15. Phase Exit Criteria (2 → 3, then 3 → 4)

**To exit Phase 2 (Alpha) → Phase 3 (Beta / feature-complete):**
- [ ] `--test` reflects computed results, not literals (D1 closed).
- [ ] Real threaded pipeline covered by an automated integration test (backlog #4).
- [ ] Correlation bounded; documented sustained-EPS ceiling (D2, #2, #12).
- [ ] Behavioral baseline active (D4) and SOAR either real or explicitly labeled roadmap (D5).
- [ ] ML + FastAPI + dashboard verified on the target with the bundled venv.

**To exit Phase 3 (Beta) → Phase 4 (Release Candidate / hardened):**
- [ ] Mandatory auth + RBAC; syslog/network defaults hardened; model artifacts signed.
- [ ] Load/soak test passing at the published EPS ceiling with stable memory.
- [ ] Security test tier (authz, input abuse, deserialization) in CI.
- [ ] Cross-platform packaging + reproducible build.
- [ ] Test coverage extended beyond smoke to integration + negative cases.

---

## 16. Architecture — CURRENT → NEXT → TARGET, and Roadmap

### CURRENT (verified today)
```
[Sources: file/JSON/syslog/PCAP-sim]
      → Ingest (callback) → [Q raw]
      → Normalize (worker) → [Q normalized]
      → Correlate (worker, O(n^2), unbounded)
      → Behavior + ThreatIntel + ML(heuristic) + Signature(regex)
      → Score (real weighted) → publish HIGH/CRITICAL
      → Output (JSON/CSV/CEF/console) + Alert/Case/IOC stores
   Single process · 4 threads · 3 bounded queues · graceful degradation
   Optional (unverified here): sklearn ML, YARA, FastAPI API, Streamlit dashboard, live feeds
```

### NEXT (Beta target — close Phase-2 exit criteria)
```
+ Correlation: bounded sliding-window + eviction (removes O(n^2))
+ Test mode returns computed results; integration test on real thread path
+ UEBA baseline active; SOAR real-or-labeled
+ ML/API/dashboard verified on-target; model artifacts integrity-checked
+ Accurate ops counters; config-weight validation at startup
```

### TARGET (Release-Candidate / production-viable on-prem SIEM)
```
+ Mandatory auth + RBAC + audit-linked identity
+ Horizontal option: queue backend (e.g. broker) for multi-worker scale
+ Managed detection content (rules/IOCs) update pipeline
+ Standards I/O: real STIX/TAXII, ASIM-like normalized schema
+ Packaging: container + Windows service, reproducible builds, CI with
  unit + integration + load + security tiers
+ Observability: metrics/tracing, EPS ceiling enforcement, back-pressure
```

### Roadmap (phased, evidence-gated)

| Horizon | Focus | Exit signal |
|---|---|---|
| **Now → 2 wks** | Integrity & correctness: D1, D3, D6; add integration test; repo hygiene | `--test` truthful; green integration test; accurate counters |
| **2–6 wks** | Scale & detection depth: bounded correlation (D2), UEBA baseline (D4), publish EPS ceiling | Stable throughput under soak; UEBA contributes to scores |
| **6–10 wks** | On-target verification: ML (sklearn), FastAPI, dashboard, live feeds; signed model artifacts | All ◒ items promoted to ✅ on Windows target |
| **10–16 wks** | Hardening: mandatory auth + RBAC, network defaults, security test tier, packaging | Phase-4 exit criteria met |
| **16+ wks** | Platform maturity: scale-out option, managed content, standards I/O | Narrowed Sentinel gap on scale/automation |

---

### Appendix A — Evidence Log (reproducible)

| Claim | Command (run in project root) | Observed |
|---|---|---|
| Clean startup | `python3 main.py --test` | exit 0 |
| Real threaded run | `CyberEWPipeline().start(); sleep(6); get_stats(); stop()` | 289 events, queues drained, 3 real alerts, clean stop |
| Smoke suite | pytest-free runner over `tests/test_smoke.py` | 13 pass / 1 env-fail |
| ML fallback fix | probe `detect_anomalies` with `models_trained=True`, ML absent | `models_trained → False`; scores `['heuristic']` |
| Recency fix | `_calculate_recency_score` at <1h/6h/48h/10d | 1.0 / 0.8 / 0.5 / 0.2 |
| Scoring discrimination | multi-source malicious vs benign | 0.971/critical vs ~0.31 |
| Scoring throughput | 5,000 scored events, timed | ~57,000 ev/s |
| Correlation O(n²) | end-to-end rate over run | 4,945 → 532 ev/s as state grows |

### Appendix B — Files changed in this audit
1. `core/engines/ml_anomaly_engine.py` — reset `models_trained=False` in heuristic-only branch (commented).
2. `core/engines/scoring_engine.py` — timezone-safe recency (`datetime_now_utc`/`ensure_utc`; import added; commented).

*Both changes are surgical, commented at the change site, and re-verified. No other project files were modified.*

