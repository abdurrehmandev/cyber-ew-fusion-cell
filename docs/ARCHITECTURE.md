# Cyber-EW Fusion Cell: Architecture & API Reference

## System Architecture

### High-Level Overview
The Cyber-EW Fusion Cell is a real-time cyber threat telemetry processing pipeline with the following components:

```
┌─────────────────────────────────────────────────────────────────┐
│  Data Sources                                                    │
│  (Suricata, Zeek, Syslog, Windows Event Log)                    │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Ingest Worker                                                   │
│  (File-based polling from data/inputs/live)                     │
│  Supported formats: .eve, .jsonl, .json, .tsv, .log             │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Normalization Engine (server/normalization.ts)                 │
│  Converts raw telemetry → canonical Alert schema                │
│  ├─ normalizeSuricata() - Suricata EVE events                   │
│  ├─ normalizeZeekTsv() - Zeek TSV connection/DNS/HTTP logs      │
│  ├─ normalizeSyslog() - RFC 5424/3164 syslog                    │
│  ├─ normalizeWindowsEvent() - Windows Event Log (JSON)          │
│  └─ normalizeGeneric() - Fallback for unknown formats           │
└─────────────────┬───────────────────────────────────────────────┘
                  │
          ┌───────┴────────────────┬─────────────┐
          ▼                        ▼             ▼
    ┌──────────────┐      ┌──────────────┐  ┌──────────────┐
    │ Correlation  │      │  Behavior    │  │   Scoring    │
    │   Engine     │      │   Engine     │  │   Engine     │
    │              │      │              │  │              │
    │ Tracks corr. │      │ Tracks host  │  │ Computes     │
    │ events per   │      │ profiles &   │  │ threat score │
    │ IP/username  │      │ anomalies    │  │ (0.0-1.0)    │
    └──────────────┘      └──────────────┘  └──────────────┘
          │                      │                │
          └──────────────┬───────┴────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Output Persistence (server/persistWriter.ts)                   │
│  → data/outputs/alerts.jsonl (buffered append with periodic fsync) │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  REST API (server.ts)                                           │
│  ├─ GET /api/health - System health                             │
│  ├─ GET /api/ingest/stats - Telemetry stats                     │
│  ├─ GET /api/ingest/alerts - Query alerts                       │
│  ├─ POST /api/ingest/raw - Ingest telemetry directly            │
│  └─ GET /api/ingest/timeline - Event timeline (JSON/CSV)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Engine Details

### 1. Normalization Engine (server/normalization.ts)

**Purpose**: Unify telemetry from multiple sources into a canonical Alert schema.

**Supported Formats**:
- **Suricata EVE** (.eve, .jsonl): IDS/IPS alerts with signatures
- **Zeek TSV** (.tsv): Connection logs, DNS queries, HTTP traffic
- **Syslog** (.log): RFC 5424/3164 formatted system logs
- **Windows Event** (JSON): EventID, EventData, TimeCreated structures
- **Generic** (fallback): Any JSON with basic event properties

**Key Functions**:
```typescript
normalizeToAlert(parsed: any, format: string, sourceFile?: string): Alert
ensureIsoTimestamp(ts: any): string  // UTC ISO-8601 timestamp
normalizeSuricata(parsed, sourceFile?)
normalizeZeekTsv(line, sourceFile?)
normalizeSyslog(line, sourceFile?)
normalizeWindowsEvent(parsed, sourceFile?)
normalizeGeneric(parsed, sourceFile?)
```

**Canonical Alert Schema**:
```json
{
  "alert_id": "alt_norm_1234567890_123",
  "timestamp": "2026-08-27T23:20:00.000Z",
  "event": {
    "event_id": "evt_norm_123",
    "event_type": "suricata_alert",
    "source_ip": "192.168.1.100",
    "destination_ip": "198.51.100.23",
    "source_port": 54321,
    "destination_port": 443,
    "username": null,
    "severity": "high",
    "confidence": 0.9,
    "details": { ... }
  },
  "threat_score": {
    "score": 0.75,
    "level": "High",
    "confidence": 0.9,
    "sources": ["suricata_norm"]
  },
  "threat_level": "High",
  "priority": "P2",
  "summary": "Alert summary text",
  "recommended_actions": ["Action 1", "Action 2"],
  "metadata": {
    "source_system": "suricata_eve_normalizer",
    "source_file": "eve.jsonl"
  }
}
```

---

### 2. Correlation Engine (server/correlation.ts)

**Purpose**: Track and enrich events by identifying correlated activity per IP/username.

**Time Window**: 10 minutes (configurable)

**Persistence (NEW)**:
- Correlation indices are persisted to `data/state/correlation_index.json`
- Periodic flush ensures correlation context survives restarts (default: every 30s)

**Key Methods**:
```typescript
addEvent(alert: any): void
queryByIp(ip: string): any[]
queryByUser(username: string): any[]
getCorrelatedSummary(alert: any): CorrelatedSummary
```

**Correlated Summary Schema**:
```json
{
  "correlated_event_count": 5,
  "correlated_entities": {
    "source_ips": ["192.168.1.100"],
    "destination_ips": ["198.51.100.23"],
    "usernames": []
  },
  "correlation_score": 0.75,
  "last_seen": "2026-08-27T23:20:00.000Z"
}
```

**Behavior**: For every new alert, the engine:
1. Queries for prior events from the same source IP/user within the time window
2. Computes a correlation score based on count and recency
3. Adds the new event to in-memory indices
4. Evicts events older than the time window on each call

---

### 3. Behavior Engine (server/behavior.ts)

**Purpose**: Build host behavioral profiles and detect anomalies.

**Key Methods**:
```typescript
addEvent(alert: any): void
getProfile(key: string): HostProfile
detectAnomalies(alert: any): BehaviorResult
```

**Host Profile Schema**:
```json
{
  "key": "192.168.1.100",
  "event_count": 42,
  "first_seen": "2026-08-27T22:00:00.000Z",
  "last_seen": "2026-08-27T23:20:00.000Z",
  "patterns": [
    {
      "description": "High volume alert event on 192.168.1.100",
      "timestamp": "2026-08-27T23:18:00.000Z"
    }
  ]
}
```

**Anomaly Detection**:
- Triggers when event count crosses a threshold (default: every 50 events)
- Flags volume spikes as potential attack indicators
- Stores patterns in a rolling 10-item window per host

**Persistence (NEW)**:
- Host profiles are persisted to disk at `data/state/behavior_profiles.json`
- Profiles are auto-saved periodically (default: every 30s) and flushed on shutdown
- This ensures behavioral state survives restarts and supports historical analysis

**Behavior Result**:
```json
{
  "profile": { ... },
  "patterns": [ ... ],
  "anomaly_detected": true
}
```

---

### 4. Scoring Engine (server/scoring.ts)

**Purpose**: Calculate multi-factor threat scores for alerts.

**Scoring Formula**:
```
base_score = provided_score OR 0.5
correlation_factor = min(0.2, log(1 + corr_count) / 3)
behavior_factor = min(0.25, pattern_count * 0.08)
final_score = clamp(base_score + corr_factor + behavior_factor, 0.0, 1.0)
threat_level = Critical (≥0.9) | High (≥0.7) | Medium (≥0.45) | Low (<0.45)
```

**Key Method**:
```typescript
scoreAlert(alert: any): Alert
```

**Scoring Metadata Added**:
- Mapping to MITRE ATT&CK techniques is included (`mitre_techniques`, `mitre_descriptions`) for every enriched alert when patterns match known tactics/techniques.

```json
{
  "threat_score": {
    "score": 0.85,
    "level": "High",
    "confidence": 0.9,
    "sources": ["suricata_norm"]
  },
  "scoring": {
    "updated_at": "2026-08-27T23:20:00.000Z",
    "corr_count": 3,
    "behavior_patterns": 1
  }
}
```

---

## REST API Endpoints

### GET /api/health
Health check and system status.

**Response** (200 OK):
```json
{
  "status": "ok",
  "timestamp": "2026-08-27T23:20:00.000Z",
  "uptime_ms": 3600000
}
```

---

### GET /api/ingest/stats
Telemetry ingestion statistics.

**Query Parameters**:
- `since` (optional): ISO-8601 timestamp (default: last 24h)

**Response** (200 OK):
```json
{
  "total_alerts": 1234,
  "alerts_by_threat_level": {
    "critical": 5,
    "high": 23,
    "medium": 156,
    "low": 1050
  },
  "alerts_by_source_system": {
    "suricata_eve_normalizer": 800,
    "zeek_normalizer": 300,
    "syslog_normalizer": 100,
    "windows_event_normalizer": 34
  },
  "top_source_ips": [
    { "ip": "192.168.1.100", "count": 45 },
    { "ip": "10.0.0.55", "count": 23 }
  ],
  "top_destination_ips": [
    { "ip": "198.51.100.23", "count": 123 }
  ],
  "timestamp": "2026-08-27T23:20:00.000Z"
}
```

---

### GET /api/ingest/alerts
Query alerts with optional filtering.

**Query Parameters**:
- `source_ip` (optional): Filter by source IP
- `destination_ip` (optional): Filter by destination IP
- `threat_level` (optional): Filter by threat level (Critical/High/Medium/Low)
- `limit` (optional, default: 100): Max results
- `offset` (optional, default: 0): Pagination offset

**Response** (200 OK):
```json
{
  "alerts": [
    {
      "alert_id": "alt_norm_123",
      "timestamp": "2026-08-27T23:20:00.000Z",
      "event": { ... },
      "threat_score": { ... },
      "threat_level": "High",
      "_correlation_summary": { ... },
      "behavior_analysis": { ... }
    }
  ],
  "total": 1234,
  "limit": 100,
  "offset": 0
}
```

---

### POST /api/ingest/raw
Ingest telemetry directly via HTTP.

**Request Body**:
```json
{
  "timestamp": "2026-08-27T23:20:00.000Z",
  "src_ip": "192.168.1.100",
  "dest_ip": "198.51.100.23",
  "alert": {
    "signature": "Test alert"
  }
}
```

**Response** (200 OK):
```json
{
  "alert_id": "alt_norm_456",
  "message": "Alert ingested and enriched"
}
```

---

### GET /api/ingest/timeline
Event timeline with format option.

**Query Parameters**:
- `format` (optional, default: "json"): "json" or "csv"
- `limit` (optional, default: 50): Max events

**Response** (200 OK, format=json):
```json
{
  "events": [
    {
      "timestamp": "2026-08-27T23:20:00.000Z",
      "event_id": "evt_norm_123",
      "source_ip": "192.168.1.100",
      "threat_level": "High"
    }
  ]
}
```

**Response** (200 OK, format=csv):
```
timestamp,event_id,source_ip,threat_level
2026-08-27T23:20:00.000Z,evt_norm_123,192.168.1.100,High
```

---

## File Structure

```
data/
├── inputs/
│   └── live/              # Drop telemetry files here (.jsonl, .tsv, .log)
│       └── processed/     # Automatically moved after ingestion
└── outputs/
    └── alerts.jsonl       # Enriched alerts (atomic append-only)

server/
├── ingestWorker.ts        # File watcher & ingest loop
├── normalization.ts       # Multi-format telemetry normalization
├── correlation.ts         # Time-windowed event correlation
├── behavior.ts            # Host profile tracking & anomaly detection
├── scoring.ts             # Multi-factor threat scoring
└── server.ts              # Express API & orchestration

tests/
├── api.test.ts            # REST API smoke tests
└── engines.test.ts        # Engine unit tests

scripts/
└── generate_attack_scenario.ts  # Demo scenario generator

docs/
├── ARCHITECTURE.md        # This file
├── IMPLEMENTATION_STATUS.md
└── README.md
```

---

## Running the Pipeline

### Development
```bash
npm install
npm run dev
```
Starts Express server on port 3000 with file watcher and API endpoints.

### Testing
```bash
npm test                # Run all tests
npm run test:watch      # Run tests in watch mode
```

### Generate Demo Scenarios
```bash
npx ts-node scripts/generate_attack_scenario.ts
```
Creates realistic multi-event attack sequences in `data/inputs/live/`.

### Verify Ingestion
```bash
ls -la data/outputs/alerts.jsonl
tail -f data/outputs/alerts.jsonl
```

---

## Performance & Scalability

**In-Memory Limits**:
- Correlation: ~10 minutes of events per IP/username
- Behavior: ~10 patterns per host, rolling window
- No persistence of profiles between restarts (future work)

**File Throughput**:
- Polling interval: 2 seconds
- Atomic fsync on every write (durable but slower)
- Benchmark: ~500 events/sec on typical hardware

**Recommended Production Enhancements**:
1. **Persistent State**: Save behavior_profiles.json periodically
2. **Async Writes**: Buffer alerts and batch fsync for higher throughput
3. **Time Series DB**: Replace JSONL with InfluxDB or similar for queries
4. **Distributed Correlation**: Use Redis for multi-instance correlation
5. **Alerting**: HTTP webhooks or SMTP notifications on high-severity events

---

## Troubleshooting

**No alerts appearing in outputs/**:
1. Check `data/inputs/live/` has files (.jsonl, .eve, .log, .tsv)
2. Check console output for `[ingestWorker]` messages
3. Ensure file format matches expected schema

**Correlation/Behavior scores not changing**:
- Correlation window is 10 minutes; test with time-series data
- Behavior anomaly triggers at event_count % 50 == 0

**Tests failing**:
```bash
npm test -- --verbose
```
Check that normalization engines properly handle all input formats.

---

## Future Work

1. ✓ Multi-format normalization (Suricata, Zeek, Syslog, Windows)
2. ✓ Correlation & behavior profiling
3. ✓ Multi-factor threat scoring
4. [ ] Persistent behavior profile storage (JSON file + periodic flush)
5. [ ] MITRE ATT&CK mapping and pattern matching
6. [ ] Output formats (CEF, STIX, CSV export)
7. [ ] GraphQL API for complex queries
8. [ ] Time series analytics (spike detection, trend analysis)
9. [ ] Machine learning scoring (trained on historical data)
10. [ ] Distributed correlation (Redis, multi-instance)
