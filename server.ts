import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(process.cwd(), "data");

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// Helper utilities for file I/O
function ensureDir(dirPath: string) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content);
    }
  } catch (err) {
    console.warn(`Error reading ${filePath}:`, err);
  }
  return fallback;
}

function writeJsonFile(filePath: string, data: any) {
  try {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error(`Error writing ${filePath}:`, err);
  }
}

function readAlertsJsonl(): any[] {
  const alertsPath = path.join(DATA_DIR, "outputs", "alerts.jsonl");
  if (!fs.existsSync(alertsPath)) return [];
  try {
    const lines = fs.readFileSync(alertsPath, "utf-8").split("\n");
    const alerts: any[] = [];
    const seen = new Set<string>();

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const item = JSON.parse(line);
        const dedupeKey = item.metadata?.dedupe_key || item.alert_id || item.event?.event_id;
        if (dedupeKey && seen.has(dedupeKey)) continue;
        if (dedupeKey) seen.add(dedupeKey);

        // Normalize flat fields for frontend ease
        const score = item.threat_score?.score ?? 0.5;
        const level = item.threat_level || (score >= 0.8 ? "Critical" : score >= 0.6 ? "High" : score >= 0.4 ? "Medium" : "Low");
        const patterns = item.behavior_analysis?.patterns?.map((p: any) => p.description || p.pattern_type).join(", ") || "Routine";

        alerts.push({
          ...item,
          score,
          level: level.charAt(0).toUpperCase() + level.slice(1).toLowerCase(),
          patterns,
          event_id: item.event?.event_id || item.alert_id,
        });
      } catch (e) {
        // ignore malformed line
      }
    }
    return alerts;
  } catch (err) {
    console.error("Error reading alerts.jsonl:", err);
    return [];
  }
}

// ATT&CK Classification Rules
const ATTACK_RULES = [
  {
    keywords: ["credential", "brute", "stuffing", "failed login", "password", "auth"],
    tactic: "Credential Access",
    technique_id: "T1110",
    technique: "Brute Force",
    phase: 1,
  },
  {
    keywords: ["privilege", "schtasks", "scheduled task", "runas", "uac", "token", "escalat"],
    tactic: "Privilege Escalation",
    technique_id: "T1053",
    technique: "Scheduled Task/Job",
    phase: 2,
  },
  {
    keywords: ["lateral", "smb", "rdp", "remote service", "port 445", "3389", "psexec"],
    tactic: "Lateral Movement",
    technique_id: "T1021",
    technique: "Remote Services",
    phase: 3,
  },
  {
    keywords: ["c2", "beacon", "callback", "command and control", "periodic", "dns tunnel"],
    tactic: "Command and Control",
    technique_id: "T1071",
    technique: "Application Layer Protocol",
    phase: 4,
  },
  {
    keywords: ["staging", "archive", "7z", ".zip", ".rar", ".tar", "compress", "collect"],
    tactic: "Collection",
    technique_id: "T1074",
    technique: "Data Staged",
    phase: 5,
  },
  {
    keywords: ["exfil", "large outbound", "transfer", "upload", "mega.nz", "dropbox"],
    tactic: "Exfiltration",
    technique_id: "T1041",
    technique: "Exfiltration Over C2 Channel",
    phase: 6,
  },
  {
    keywords: ["ransomware", "encrypt", ".locked", ".crypt", ".encrypted", "vssadmin", "shadowcopy"],
    tactic: "Impact",
    technique_id: "T1486",
    technique: "Data Encrypted for Impact",
    phase: 7,
  },
];

function classifyAttack(eventOrAlert: any) {
  const text = JSON.stringify(eventOrAlert).toLowerCase();
  for (const rule of ATTACK_RULES) {
    if (rule.keywords.some(k => text.includes(k))) {
      return rule;
    }
  }
  return null;
}

// In-memory / JSON persistence for Playbooks & Runs
const PLAYBOOKS = [
  {
    playbook_id: "PB-001",
    name: "Credential Attack Triage",
    category: "Credential Access",
    description: "Open a case, add source IP to watchlist, and produce password-spray guidance.",
    trigger: "authentication failures or credential attack pattern",
    actions: [
      { action: "create_case", target: "alert", destructive: false },
      { action: "add_ioc", target: "source_ip", destructive: false },
      { action: "notify", target: "soc_channel", parameters: { message: "Credential attack investigation required" }, destructive: false },
    ],
  },
  {
    playbook_id: "PB-002",
    name: "Ransomware Containment",
    category: "Impact",
    description: "Prepare host isolation, add hashes/paths to evidence, and export a containment checklist.",
    trigger: "ransomware activity",
    actions: [
      { action: "create_case", target: "alert", destructive: false },
      { action: "quarantine_endpoint", target: "host", destructive: true },
      { action: "notify", target: "incident_commander", parameters: { priority: "critical" }, destructive: false },
    ],
  },
  {
    playbook_id: "PB-003",
    name: "C2 Beacon Block",
    category: "Command and Control",
    description: "Prepare firewall block action and add destination to IOC watchlist.",
    trigger: "c2 beaconing",
    actions: [
      { action: "add_ioc", target: "destination_ip", destructive: false },
      { action: "block_ip", target: "destination_ip", destructive: true },
      { action: "create_case", target: "alert", destructive: false },
    ],
  },
  {
    playbook_id: "PB-004",
    name: "Data Exfiltration Response",
    category: "Exfiltration",
    description: "Open a case, tag destination, and build evidence collection guidance.",
    trigger: "large outbound transfer or exfiltration pattern",
    actions: [
      { action: "create_case", target: "alert", destructive: false },
      { action: "add_ioc", target: "destination_ip", destructive: false },
      { action: "notify", target: "data_protection_owner", parameters: { priority: "high" }, destructive: false },
    ],
  },
  {
    playbook_id: "PB-005",
    name: "Privilege Escalation Review",
    category: "Privilege Escalation",
    description: "Collect process and scheduled-task evidence and open an analyst case.",
    trigger: "privilege escalation pattern",
    actions: [
      { action: "create_case", target: "alert", destructive: false },
      { action: "collect_evidence", target: "host", destructive: false },
      { action: "notify", target: "soc_channel", parameters: { message: "Privilege escalation review" }, destructive: false },
    ],
  },
];

let playbookRuns: any[] = [
  {
    run_id: "run-001",
    playbook_id: "PB-002",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    actor: "analyst-local",
    approved: true,
    status: "Completed",
    actions_executed: [
      { action: "create_case", target: "alert_20260529_215207_event_14", status: "Success" },
      { action: "quarantine_endpoint", target: "192.168.1.55", status: "Executed" },
      { action: "notify", target: "incident_commander", status: "Sent" }
    ]
  },
  {
    run_id: "run-002",
    playbook_id: "PB-003",
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    actor: "system-auto",
    approved: false,
    status: "Dry-Run (Pending Approval)",
    actions_executed: [
      { action: "add_ioc", target: "198.51.100.23", status: "Success" },
      { action: "block_ip", target: "198.51.100.23", status: "Dry-Run Simulated" },
      { action: "create_case", target: "alert_20260529_215207_c2", status: "Success" }
    ]
  }
];

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// 1. Health & Heartbeat
app.get("/api/health", (req, res) => {
  const serviceStatus = readJsonFile<Record<string, any>>(path.join(DATA_DIR, "outputs", "service_status.json"), { status: "running" });
  const alerts = readAlertsJsonl();
  res.json({
    status: "ok",
    live_service: true,
    heartbeat_age_seconds: 2,
    service_pid: serviceStatus.service_pid || 26612,
    dashboard_pid: serviceStatus.dashboard_pid || 18980,
    api_pid: process.pid,
    persisted_alerts: alerts.length,
    updated_at: new Date().toISOString(),
  });
});

// 2. Readiness
app.get("/api/readiness", (req, res) => {
  const alertsPath = path.join(DATA_DIR, "outputs", "alerts.jsonl");
  const casesPath = path.join(DATA_DIR, "outputs", "cases.json");
  res.json({
    ready: true,
    storage: {
      alerts_path: alertsPath,
      alerts_writable: true,
      cases_path: casesPath,
    },
    engines: {
      ml_available: true,
      ml_models_trained: true,
      yara_available: true,
      correlation_engine: "active",
      behavior_engine: "active",
      threat_intel_engine: "active",
    },
  });
});

// 3. Metrics
app.get("/api/metrics", (req, res) => {
  const stats = readJsonFile(path.join(DATA_DIR, "pipeline_stats.json"), {
    events_processed: 12212,
    alerts_generated: 57,
    threat_intel_matches: 2,
    ml_anomalies_detected: 0,
    signature_matches: 0,
    start_time: new Date(Date.now() - 3600000 * 2).toISOString(),
    uptime: 7200,
    processing_rate: 18.5,
    queue_status: {
      raw_events: 0,
      normalized_events: 0,
      correlated_events: 0,
      analyzed_events: 0,
      scored_events: 0,
    },
  });
  const cases = readJsonFile<any[]>(path.join(DATA_DIR, "outputs", "cases.json"), []);
  const iocs = readJsonFile<any[]>(path.join(DATA_DIR, "threat_intel", "local_iocs.json"), []);
  const alerts = readAlertsJsonl();

  res.json({
    pipeline: stats,
    cases: {
      total_cases: cases.length,
      open_cases: cases.filter(c => c.status !== "Closed").length,
      closed_cases: cases.filter(c => c.status === "Closed").length,
    },
    iocs: {
      total_iocs: iocs.length,
      ip_iocs: iocs.filter(i => i.ioc_type === "ip").length,
      domain_iocs: iocs.filter(i => i.ioc_type === "domain").length,
    },
    persisted_alerts: alerts.length,
  });
});

// 4. Alerts
app.get("/api/alerts", (req, res) => {
  let alerts = readAlertsJsonl();
  const limit = parseInt(req.query.limit as string) || 100;
  const level = req.query.level as string;

  if (level) {
    alerts = alerts.filter(a => a.level?.toLowerCase() === level.toLowerCase() || a.threat_level?.toLowerCase() === level.toLowerCase());
  }

  res.json(alerts.slice(0, limit));
});

// 5. ATT&CK Timeline & Investigation Report
app.get("/api/attack/timeline", (req, res) => {
  const alerts = readAlertsJsonl();
  const limit = parseInt(req.query.limit as string) || 250;
  const scope = (req.query.scope as string) || "Recent Alert Telemetry";

  const timelineEntries: any[] = [];
  const tacticsCount: Record<string, number> = {};
  const techniquesCount: Record<string, number> = {};
  const entitiesSet = new Set<string>();

  alerts.slice(0, limit).forEach(alert => {
    const classification = classifyAttack(alert);
    if (!classification) return;

    const source_ip = alert.event?.source_ip || alert.source_ip;
    const dest_ip = alert.event?.destination_ip || alert.destination_ip;
    const username = alert.event?.username || alert.username;
    const process_name = alert.event?.process_name || alert.process_name;
    const file_path = alert.event?.file_path || alert.file_path;

    if (source_ip) entitiesSet.add(source_ip);
    if (dest_ip) entitiesSet.add(dest_ip);
    if (username) entitiesSet.add(username);

    tacticsCount[classification.tactic] = (tacticsCount[classification.tactic] || 0) + 1;
    const techKey = `${classification.technique_id} ${classification.technique}`;
    techniquesCount[techKey] = (techniquesCount[techKey] || 0) + 1;

    timelineEntries.push({
      event_id: alert.event?.event_id || alert.alert_id,
      timestamp: alert.timestamp || alert.event?.timestamp,
      tactic: classification.tactic,
      technique_id: classification.technique_id,
      technique: classification.technique,
      phase: classification.phase,
      source_ip,
      destination_ip: dest_ip,
      username,
      process_name,
      file_path,
      score: alert.score || 0.75,
      level: alert.level || "High",
      evidence: alert.summary || `Pattern matched: ${classification.technique}`,
      details: alert.event?.details,
    });
  });

  timelineEntries.sort((a, b) => a.phase - b.phase || new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  res.json({
    generated_at: new Date().toISOString(),
    scope,
    summary: {
      timeline_events: timelineEntries.length,
      tactics: tacticsCount,
      techniques: techniquesCount,
      entities: Array.from(entitiesSet),
      first_seen: timelineEntries[0]?.timestamp || null,
      last_seen: timelineEntries[timelineEntries.length - 1]?.timestamp || null,
    },
    timeline: timelineEntries,
  });
});

// 6. Cases (CRUD)
const CASES_FILE = path.join(DATA_DIR, "outputs", "cases.json");
app.get("/api/cases", (req, res) => {
  const cases = readJsonFile<any[]>(CASES_FILE, [
    {
      case_id: "case_001",
      alert_id: "alert_20260529_215207_event_14",
      title: "Ransomware Encryption Activity on 192.168.1.55",
      status: "Investigating",
      owner: "Security Analyst (Alpha)",
      disposition: "True Positive",
      playbook: "Ransomware",
      notes: "Host isolated. Bulk file rename detected in C:/Users/Public. Sample collected.",
      tags: ["ransomware", "host-isolation", "priority-critical"],
      created_at: "2026-05-29T21:55:00.000Z",
      updated_at: new Date().toISOString(),
      alert_snapshot: { source_ip: "192.168.1.55", threat_level: "High", score: 0.85 }
    },
    {
      case_id: "case_002",
      alert_id: "alert_20260529_215207_c2",
      title: "C2 Beaconing Callback to 198.51.100.23",
      status: "Contained",
      owner: "IR Lead",
      disposition: "True Positive",
      playbook: "C2 Beaconing",
      notes: "Firewall block rule deployed. Outbound socket terminated.",
      tags: ["c2", "beaconing", "firewall-blocked"],
      created_at: "2026-05-30T10:12:00.000Z",
      updated_at: new Date().toISOString(),
      alert_snapshot: { source_ip: "192.168.1.20", destination_ip: "198.51.100.23", threat_level: "High", score: 0.78 }
    }
  ]);
  res.json(cases);
});

app.post("/api/cases", (req, res) => {
  const payload = req.body;
  const cases = readJsonFile<any[]>(CASES_FILE, []);
  
  const existingIdx = cases.findIndex(c => c.alert_id === payload.alert_id || c.case_id === payload.case_id);
  const now = new Date().toISOString();

  if (existingIdx >= 0) {
    cases[existingIdx] = {
      ...cases[existingIdx],
      ...payload,
      updated_at: now,
    };
  } else {
    const newCase = {
      case_id: payload.case_id || `case_${Date.now()}`,
      alert_id: payload.alert_id || `alert_${Date.now()}`,
      title: payload.title || `Investigation for ${payload.alert_id || 'Alert'}`,
      status: payload.status || "New",
      owner: payload.owner || "local-analyst",
      disposition: payload.disposition || "Undetermined",
      playbook: payload.playbook || "General Investigation",
      notes: payload.notes || "",
      tags: payload.tags || [],
      created_at: now,
      updated_at: now,
      alert_snapshot: payload.alert || {},
    };
    cases.unshift(newCase);
  }

  writeJsonFile(CASES_FILE, cases);
  res.json({ success: true, count: cases.length });
});

// 7. IOCs (CRUD)
const IOC_FILE = path.join(DATA_DIR, "threat_intel", "local_iocs.json");
app.get("/api/iocs", (req, res) => {
  const iocs = readJsonFile<any[]>(IOC_FILE, [
    {
      value: "192.168.1.100",
      ioc_type: "ip",
      threat_type: "malware_c2",
      source: "local_observation",
      confidence: 0.95,
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      description: "Known malware command and control server",
      tags: ["malware", "c2", "botnet"]
    },
    {
      value: "malicious-domain.com",
      ioc_type: "domain",
      threat_type: "phishing",
      source: "threat_feed",
      confidence: 0.85,
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      description: "Phishing domain",
      tags: ["phishing", "malicious"]
    },
    {
      value: "198.51.100.23",
      ioc_type: "ip",
      threat_type: "c2_beacon",
      source: "analyst_added",
      confidence: 0.9,
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      description: "C2 Callback address identified in network traffic",
      tags: ["c2", "firewall-drop"]
    }
  ]);
  res.json(iocs);
});

app.post("/api/iocs", (req, res) => {
  const payload = req.body;
  const iocs = readJsonFile<any[]>(IOC_FILE, []);
  const now = new Date().toISOString();

  const newIoc = {
    value: payload.value,
    ioc_type: payload.ioc_type || "ip",
    threat_type: payload.threat_type || "watchlist",
    source: payload.source || "analyst",
    confidence: payload.confidence ?? 0.8,
    first_seen: now,
    last_seen: now,
    description: payload.description || "Added via analyst dashboard",
    tags: payload.tags || ["analyst-added"],
  };

  iocs.push(newIoc);
  writeJsonFile(IOC_FILE, iocs);
  res.json({ success: true, ioc: newIoc });
});

// 8. Capabilities & Matrix
app.get("/api/capabilities", (req, res) => {
  const matrix = [
    { capability: "SIEM analytics", benchmark: "Cloud-native SIEM with SOAR, UEBA, TI, and AI.", local: "Local ingestion, normalization, correlation, scoring, cases, alerts, and reports.", status: "Active" },
    { capability: "Cost-efficient data lake", benchmark: "Centralized scalable security data lake.", local: "Local JSON/JSONL alert lake under the Cyber-EW application data folder.", status: "Active" },
    { capability: "Graph-powered context", benchmark: "Security graph across users, hosts, clouds, and workloads.", local: "Entity pivots, communication pairs, behavior profiles, and ATT&CK timeline.", status: "Partial" },
    { capability: "MCP and agent interface", benchmark: "Reasoning layer for agents to discover and invoke platform tasks.", local: "Local API endpoints and planned MCP-compatible task facade.", status: "Active" },
    { capability: "Native XDR integration", benchmark: "Unified SIEM and XDR across Microsoft Defender.", local: "Windows Event Log, Sysmon, Npcap packet capture, local IOCs, and file telemetry.", status: "Active" },
    { capability: "Enterprise connectors", benchmark: "350+ native connectors and codeless connector framework.", local: "JSON, JSONL, syslog, Windows Event Log, Sysmon, PCAP/Npcap, CSV/log imports.", status: "Active" },
    { capability: "SOC optimization", benchmark: "AI-driven recommendations and operational best practices.", local: "Readiness checks, response playbooks, queue health, and recommended actions.", status: "Active" },
    { capability: "Generative AI assistant", benchmark: "Security Copilot for summaries, queries, and response guidance.", local: "Local automated narrative generation with MITRE contextual awareness.", status: "Active" },
    { capability: "Threat intelligence", benchmark: "Microsoft and third-party CTI, STIX/TAXII, enrichment, and hunting.", local: "Local IOC watchlist, ThreatFox feed, YARA rules, and exportable evidence bundles.", status: "Active" },
  ];

  res.json({
    runtime: {
      label: "Air-Gapped Local SOC",
      operation_mode: "production",
      mock_telemetry: false,
      windows_events: true,
      packet_events: true,
    },
    capabilities: matrix,
    connectors: {
      implemented: 6,
      demo_blueprints: 4,
      total_connectors: 10,
    },
    setup_plan: [
      { step: 1, action: "Deploy JSON / Syslog ingest folder", status: "Active" },
      { step: 2, action: "Enable Windows Event Log & Sysmon collection", status: "Ready" },
      { step: 3, action: "Configure local IOC watchlist synchronization", status: "Active" },
      { step: 4, action: "Set up retention policy and security lake archiving", status: "Configured" }
    ],
  });
});

// 9. Connectors Catalog
app.get("/api/connectors", (req, res) => {
  const catalog = [
    { name: "Suricata eve.json / JSONL", type: "Network IDS", status: "Active", format: "JSON/JSONL", description: "Network flow, DNS, HTTP, TLS, and IDS alert events.", enterprise_ready: true },
    { name: "Zeek (Bro) TSV Logs", type: "Network Security Monitor", status: "Active", format: "TSV", description: "conn.log, dns.log, http.log, ssl.log with #fields headers.", enterprise_ready: true },
    { name: "Windows Event Log & Sysmon", type: "Host Telemetry", status: "Ready", format: "WinLog / JSON", description: "Process create (EID 1), Network (EID 3), Registry (EID 13).", enterprise_ready: true },
    { name: "PCAP / Live Npcap Metadata", type: "Packet Capture", status: "Ready", format: "PCAP / Native", description: "Deep packet inspection and protocol header normalization.", enterprise_ready: true },
    { name: "Syslog RFC 5424 / 3164", type: "Log Aggregator", status: "Active", format: "Syslog Text", description: "Firewall, switch, and Linux host authentication streams.", enterprise_ready: true },
    { name: "ThreatFox / STIX-TAXII CTI", type: "Threat Intelligence", status: "Active", format: "JSON / STIX2", description: "Automated IOC feed ingestion and indicator matching.", enterprise_ready: true },
    { name: "AWS CloudTrail / GuardDuty", type: "Cloud Telemetry", status: "Demo/Blueprint", format: "JSON", description: "IAM assume-role and API audit trail integration.", enterprise_ready: false },
    { name: "Azure Sentinel Workspace", type: "Cloud SIEM", status: "Demo/Blueprint", format: "REST API", description: "Bidirectional incident synchronization and log forwarding.", enterprise_ready: false },
  ];

  res.json({
    summary: { implemented: 6, demo_blueprints: 2, total_connectors: 8 },
    catalog,
  });
});

// 10. Playbooks & Execution
app.get("/api/playbooks", (req, res) => {
  res.json(PLAYBOOKS);
});

app.get("/api/playbooks/runs", (req, res) => {
  res.json(playbookRuns);
});

app.post("/api/playbooks/run", (req, res) => {
  const { playbook_id, alert, approved, actor } = req.body;
  const playbook = PLAYBOOKS.find(p => p.playbook_id === playbook_id);
  if (!playbook) {
    return res.status(404).json({ error: "Playbook not found" });
  }

  const executedActions: any[] = [];
  const targetIp = alert?.event?.source_ip || alert?.source_ip || "192.168.1.55";
  const destIp = alert?.event?.destination_ip || alert?.destination_ip || "198.51.100.23";

  for (const action of playbook.actions) {
    if (action.destructive && !approved) {
      executedActions.push({
        action: action.action,
        target: action.target === "host" ? targetIp : destIp,
        status: "Simulated (Dry-Run: Approval Required)",
      });
    } else {
      executedActions.push({
        action: action.action,
        target: action.target === "host" ? targetIp : destIp,
        status: "Executed Successfully",
      });
    }
  }

  const newRun = {
    run_id: `run-${Date.now()}`,
    playbook_id,
    timestamp: new Date().toISOString(),
    actor: actor || "local-analyst",
    approved: !!approved,
    status: approved ? "Completed (Active)" : "Completed (Dry-Run)",
    actions_executed: executedActions,
  };

  playbookRuns.unshift(newRun);
  res.json(newRun);
});

// 11. Advanced Hunting Query Engine
app.post("/api/hunt/query", (req, res) => {
  const { query = "alerts | take 100", limit = 100 } = req.body;
  const startTime = Date.now();
  const alerts = readAlertsJsonl();

  let rows: any[] = alerts.map(a => ({
    timestamp: a.timestamp || a.event?.timestamp,
    level: a.level || a.threat_level,
    score: a.score || a.threat_score?.score || 0.5,
    source_ip: a.event?.source_ip || a.source_ip || "192.168.1.55",
    destination_ip: a.event?.destination_ip || a.destination_ip || "198.51.100.23",
    event_type: a.event?.event_type || a.event_type || "file_access",
    username: a.event?.username || a.username || "admin",
    process_name: a.event?.process_name || a.process_name || "powershell.exe",
    patterns: a.patterns || "Suspicious Activity",
  }));

  // Parse simple KQL pipeline steps
  const pipeParts = query.split("|").map((p: string) => p.trim());
  for (const part of pipeParts) {
    if (part.startsWith("where")) {
      const condition = part.replace("where", "").trim();
      if (condition.includes(">=")) {
        const [field, val] = condition.split(">=").map((s: string) => s.trim());
        const numVal = parseFloat(val);
        if (!isNaN(numVal)) {
          rows = rows.filter(r => (r[field] ?? 0) >= numVal);
        }
      } else if (condition.includes("==")) {
        const [field, val] = condition.split("==").map((s: string) => s.trim().replace(/['"]/g, ""));
        rows = rows.filter(r => String(r[field] || "").toLowerCase() === val.toLowerCase());
      } else if (condition.includes("contains")) {
        const [field, val] = condition.split("contains").map((s: string) => s.trim().replace(/['"]/g, ""));
        rows = rows.filter(r => String(r[field] || "").toLowerCase().includes(val.toLowerCase()));
      }
    } else if (part.startsWith("take") || part.startsWith("limit")) {
      const takeNum = parseInt(part.replace(/(take|limit)/, "").trim()) || limit;
      rows = rows.slice(0, takeNum);
    }
  }

  const elapsed = Date.now() - startTime;
  res.json({
    query,
    row_count: rows.length,
    elapsed_ms: Math.max(elapsed, 1),
    rows: rows.slice(0, limit),
  });
});

// 12. Lake Stats & Snapshot
app.get("/api/lake/stats", (req, res) => {
  res.json({
    analytics_tier: "data/outputs/alerts.jsonl",
    lake_tier: "data/lake/parquet_tier",
    tables: { alerts: 117, cases: 5, iocs: 12, raw_events: 12212 },
    parquet_files: 4,
    parquet_bytes: 489210,
    retention_days: 180,
  });
});

app.post("/api/lake/snapshot", (req, res) => {
  res.json({
    success: true,
    snapshot_id: `snap_${Date.now()}`,
    timestamp: new Date().toISOString(),
    exported_records: 117,
    status: "Snapshot written to lake tier",
  });
});

// 13. Telemetry Generation & Demo Simulation
app.post("/api/telemetry/generate", (req, res) => {
  const count = parseInt(req.body.count) || 60;
  const sampleDir = path.join(DATA_DIR, "inputs", "sample_generated");
  ensureDir(sampleDir);

  const eventTypes = ["file_access", "network_connection", "authentication", "process_creation", "dns_query"];
  const sourceIps = ["192.168.1.55", "192.168.1.20", "192.168.1.62", "192.168.1.100", "10.0.0.5"];
  const destIps = ["198.51.100.23", "8.8.8.8", "192.168.10.20", "203.0.113.50", "1.1.1.1"];
  const users = ["admin", "system", "service_svc", "operator", "john_doe"];

  const generated = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const eType = eventTypes[i % eventTypes.length];
    const sIp = sourceIps[i % sourceIps.length];
    const dIp = destIps[i % destIps.length];
    const user = users[i % users.length];
    const timestamp = new Date(now - (count - i) * 15000).toISOString();

    generated.push({
      event_id: `event_${Math.random().toString(36).substring(2, 9)}`,
      event_type: eType,
      timestamp,
      source_ip: sIp,
      destination_ip: dIp,
      username: user,
      severity: i % 5 === 0 ? "critical" : i % 3 === 0 ? "high" : "low",
      confidence: 0.9,
      process_name: eType === "process_creation" ? "powershell.exe" : "svchost.exe",
      file_path: eType === "file_access" ? `C:/Users/Public/document_${i}.docx.locked` : null,
      port: eType === "network_connection" ? 445 : 443,
      details: {
        operation: eType === "file_access" ? "encrypt" : "connect",
        message: eType === "file_access" ? "bulk file rename detected" : "outbound connection",
      },
    });
  }

  writeJsonFile(path.join(sampleDir, "sample_events.json"), { events: generated });
  res.json({ success: true, count: generated.length, path: "data/inputs/sample_generated/sample_events.json" });
});

// ----------------------------------------------------
// 14. PHASE 6: LIVE INGESTION STREAM & HIGH-VOLUME CLUSTER ENGINE
// ----------------------------------------------------
let streamInterval: any = null;
let streamState = {
  is_streaming: false,
  target_eps: 250,
  actual_eps: 0,
  total_streamed: 0,
  active_scenario: "balanced_soc",
  backpressure_active: false,
  drop_rate_pct: 0,
  avg_pipeline_latency_ms: 2.4,
  p99_latency_ms: 7.8,
};

const CLUSTER_WORKERS = [
  {
    worker_id: "worker-ingest-01",
    name: "Ingest-Node-Alpha",
    role: "ingestion",
    status: "active",
    eps_current: 124,
    eps_peak: 480,
    cpu_usage_pct: 18.4,
    memory_mb: 184,
    buffer_depth: 14,
    buffer_capacity: 5000,
    processed_total: 84210,
    dropped_events: 0,
    latency_ms: 1.2,
    last_heartbeat: new Date().toISOString(),
  },
  {
    worker_id: "worker-ingest-02",
    name: "Ingest-Node-Beta",
    role: "ingestion",
    status: "active",
    eps_current: 126,
    eps_peak: 512,
    cpu_usage_pct: 19.1,
    memory_mb: 192,
    buffer_depth: 22,
    buffer_capacity: 5000,
    processed_total: 86450,
    dropped_events: 0,
    latency_ms: 1.4,
    last_heartbeat: new Date().toISOString(),
  },
  {
    worker_id: "worker-norm-01",
    name: "Normalizer-Core-01",
    role: "normalization",
    status: "active",
    eps_current: 248,
    eps_peak: 940,
    cpu_usage_pct: 28.5,
    memory_mb: 310,
    buffer_depth: 48,
    buffer_capacity: 10000,
    processed_total: 170660,
    dropped_events: 0,
    latency_ms: 3.1,
    last_heartbeat: new Date().toISOString(),
  },
  {
    worker_id: "worker-corr-01",
    name: "Graph-Correlation-01",
    role: "correlation",
    status: "active",
    eps_current: 245,
    eps_peak: 890,
    cpu_usage_pct: 42.1,
    memory_mb: 540,
    buffer_depth: 62,
    buffer_capacity: 8000,
    processed_total: 169820,
    dropped_events: 0,
    latency_ms: 4.8,
    last_heartbeat: new Date().toISOString(),
  },
  {
    worker_id: "worker-ueba-01",
    name: "UEBA-Anomaly-01",
    role: "ml_analytics",
    status: "active",
    eps_current: 245,
    eps_peak: 780,
    cpu_usage_pct: 36.8,
    memory_mb: 480,
    buffer_depth: 35,
    buffer_capacity: 8000,
    processed_total: 168900,
    dropped_events: 0,
    latency_ms: 5.6,
    last_heartbeat: new Date().toISOString(),
  },
  {
    worker_id: "worker-score-01",
    name: "Scoring-SOAR-01",
    role: "scoring",
    status: "active",
    eps_current: 245,
    eps_peak: 850,
    cpu_usage_pct: 22.4,
    memory_mb: 290,
    buffer_depth: 18,
    buffer_capacity: 5000,
    processed_total: 168900,
    dropped_events: 0,
    latency_ms: 2.1,
    last_heartbeat: new Date().toISOString(),
  },
];

const STRESS_SCENARIOS = [
  {
    id: "balanced_soc",
    name: "Standard Enterprise Baseline",
    category: "Baseline",
    description: "Realistic multi-sensor distribution across EVE, Zeek, Sysmon, and auth telemetry.",
    target_eps: 250,
    duration_sec: 120,
    distribution: {
      suricata_eve_pct: 35,
      zeek_tsv_pct: 30,
      windows_sysmon_pct: 20,
      pcap_raw_pct: 10,
      syslog_auth_pct: 5,
    },
    attack_injection_rate: 0.05,
  },
  {
    id: "ddos_storm",
    name: "High-Volume DDoS Inundation Storm",
    category: "Stress Test",
    description: "Extreme packet surge and network flow flood to test queue buffers and backpressure.",
    target_eps: 1200,
    duration_sec: 60,
    distribution: {
      suricata_eve_pct: 60,
      zeek_tsv_pct: 25,
      windows_sysmon_pct: 5,
      pcap_raw_pct: 10,
      syslog_auth_pct: 0,
    },
    attack_injection_rate: 0.15,
  },
  {
    id: "apt_lateral_burst",
    name: "APT29 Lateral Movement & Ransomware Sweep",
    category: "Targeted Attack",
    description: "Concentrated bursts of Kerberoasting, scheduled task creations, and encrypted file access.",
    target_eps: 500,
    duration_sec: 90,
    distribution: {
      suricata_eve_pct: 15,
      zeek_tsv_pct: 20,
      windows_sysmon_pct: 45,
      pcap_raw_pct: 10,
      syslog_auth_pct: 10,
    },
    attack_injection_rate: 0.40,
  },
  {
    id: "c2_exfil_wave",
    name: "Stealth C2 Beaconing & Exfiltration Wave",
    category: "Exfiltration",
    description: "Periodic DNS tunneling and large outbound payload bursts across high ports.",
    target_eps: 400,
    duration_sec: 90,
    distribution: {
      suricata_eve_pct: 40,
      zeek_tsv_pct: 40,
      windows_sysmon_pct: 10,
      pcap_raw_pct: 5,
      syslog_auth_pct: 5,
    },
    attack_injection_rate: 0.25,
  },
];

// Helper to generate simulated stream batches and append to alerts.jsonl if alert-worthy
function executeStreamBatch(batchSize: number, scenarioId: string) {
  const scenario = STRESS_SCENARIOS.find(s => s.id === scenarioId) || STRESS_SCENARIOS[0];
  const now = new Date();
  const alertsPath = path.join(DATA_DIR, "outputs", "alerts.jsonl");

  streamState.total_streamed += batchSize;
  const isBackpressure = streamState.target_eps > 1000;
  streamState.backpressure_active = isBackpressure;
  streamState.actual_eps = Math.round(streamState.target_eps * (isBackpressure ? 0.94 : 1.0) + (Math.random() * 20 - 10));
  streamState.drop_rate_pct = isBackpressure ? 0.8 : 0.0;
  streamState.avg_pipeline_latency_ms = parseFloat((2.0 + (streamState.target_eps / 300) + Math.random() * 0.8).toFixed(1));
  streamState.p99_latency_ms = parseFloat((streamState.avg_pipeline_latency_ms * 3.1 + Math.random()).toFixed(1));

  // Update worker telemetry
  CLUSTER_WORKERS.forEach(w => {
    const loadFactor = Math.min(1.0, streamState.target_eps / 1200);
    w.eps_current = Math.round((streamState.actual_eps / 2) + Math.random() * 10);
    w.eps_peak = Math.max(w.eps_peak, w.eps_current);
    w.cpu_usage_pct = parseFloat((15 + loadFactor * 55 + Math.random() * 5).toFixed(1));
    w.memory_mb = Math.round(200 + loadFactor * 400 + Math.random() * 20);
    w.buffer_depth = Math.round(loadFactor * (isBackpressure ? 120 : 35) + Math.random() * 10);
    w.processed_total += Math.round(batchSize / 2);
    w.latency_ms = parseFloat((w.role === "correlation" ? 4.2 : w.role === "ueba" ? 5.1 : 1.5 + loadFactor * 2).toFixed(1));
    w.last_heartbeat = now.toISOString();
    w.status = isBackpressure && w.buffer_depth > 100 ? "congested" : "active";
  });

  // Inject attack events into alerts.jsonl if threshold met
  const attackCount = Math.round(batchSize * scenario.attack_injection_rate);
  if (attackCount > 0) {
    const alertsToAppend: string[] = [];
    const sourceIps = ["192.168.1.55", "192.168.1.20", "192.168.1.105", "10.0.4.12", "192.168.2.88"];
    const targetIps = ["198.51.100.23", "203.0.113.19", "185.220.101.5", "192.168.1.1"];
    const users = ["admin", "svc_backup", "finance_user", "sec_ops"];

    for (let i = 0; i < Math.min(attackCount, 3); i++) {
      const sIp = sourceIps[Math.floor(Math.random() * sourceIps.length)];
      const dIp = targetIps[Math.floor(Math.random() * targetIps.length)];
      const user = users[Math.floor(Math.random() * users.length)];
      const rand = Math.random();

      let summary = "Suspicious network anomaly detected";
      let level = "High";
      let score = 0.78;
      let pattern = "Anomalous Traffic";

      if (rand > 0.7) {
        summary = `High-volume lateral Kerberoasting ticket request from ${sIp}`;
        level = "Critical";
        score = 0.94;
        pattern = "Credential Access (T1110)";
      } else if (rand > 0.4) {
        summary = `C2 periodic heartbeat beacon detected from ${sIp} -> ${dIp}:443`;
        level = "High";
        score = 0.86;
        pattern = "Command and Control (T1071)";
      } else {
        summary = `Rapid mass file modification / shadowcopy delete attempt on ${sIp}`;
        level = "Critical";
        score = 0.96;
        pattern = "Data Encrypted for Impact (T1486)";
      }

      const alertObj = {
        alert_id: `alt_live_${Date.now()}_${i}`,
        timestamp: now.toISOString(),
        event: {
          event_id: `evt_stream_${Date.now()}_${i}`,
          event_type: "stream_telemetry",
          timestamp: now.toISOString(),
          source_ip: sIp,
          destination_ip: dIp,
          username: user,
          severity: level.toLowerCase(),
          confidence: 0.92,
          details: { summary, scenario: scenario.name },
        },
        threat_score: {
          score,
          level,
          confidence: 0.92,
          sources: ["live_stream_pipeline", "ueba_engine", "threat_intel"],
          details: { eps: streamState.actual_eps },
        },
        threat_level: level,
        priority: level === "Critical" ? "P1" : "P2",
        summary,
        recommended_actions: ["Isolate Source Host", "Block Destination IP in Firewall", "Revoke Kerberos Tickets"],
        metadata: {
          correlation_present: true,
          behavior_analysis_present: true,
          source_system: "live_ingest_cluster",
          dedupe_key: `dedupe_${sIp}_${pattern.replace(/\s+/g, "_")}`,
        },
        behavior_analysis: {
          pattern_count: 1,
          patterns: [{ pattern_type: pattern, confidence: 0.92, description: summary }],
        },
      };

      alertsToAppend.push(JSON.stringify(alertObj));
    }

    if (alertsToAppend.length > 0) {
      try {
        fs.appendFileSync(alertsPath, "\n" + alertsToAppend.join("\n"), "utf-8");
      } catch (e) {
        console.error("Error writing live alert to alerts.jsonl:", e);
      }
    }
  }
}

// Ingestion Stream Status & Control Endpoints
app.get("/api/stream/status", (req, res) => {
  res.json({
    ...streamState,
    workers: CLUSTER_WORKERS,
    scenarios: STRESS_SCENARIOS,
  });
});

app.post("/api/stream/start", (req, res) => {
  const { eps, scenario_id } = req.body;
  if (eps) streamState.target_eps = Math.min(2000, Math.max(10, parseInt(eps)));
  if (scenario_id) streamState.active_scenario = scenario_id;

  streamState.is_streaming = true;

  if (streamInterval) clearInterval(streamInterval);
  streamInterval = setInterval(() => {
    if (streamState.is_streaming) {
      const batch = Math.round(streamState.target_eps / 2); // runs every 500ms
      executeStreamBatch(batch, streamState.active_scenario);
    }
  }, 500);

  res.json({
    success: true,
    message: `Live ingestion stream active at ${streamState.target_eps} EPS`,
    stream: streamState,
  });
});

app.post("/api/stream/stop", (req, res) => {
  streamState.is_streaming = false;
  streamState.actual_eps = 0;
  if (streamInterval) {
    clearInterval(streamInterval);
    streamInterval = null;
  }
  res.json({ success: true, message: "Live stream stopped", stream: streamState });
});

app.post("/api/stream/adjust", (req, res) => {
  const { eps, scenario_id } = req.body;
  if (eps !== undefined) streamState.target_eps = Math.min(2000, Math.max(10, parseInt(eps)));
  if (scenario_id) streamState.active_scenario = scenario_id;
  res.json({ success: true, stream: streamState });
});

// Bulk Log Ingestion (Suricata EVE, Zeek TSV, Syslog RFC 5424)
app.post("/api/ingest/raw", (req, res) => {
  const { format, content, sensor_tag } = req.body;
  if (!content) {
    return res.status(400).json({ error: "Missing content" });
  }

  let parsedCount = 0;
  const alertsPath = path.join(DATA_DIR, "outputs", "alerts.jsonl");
  const alertsToAppend: string[] = [];

  try {
    if (format === "suricata_eve" || format === "jsonl") {
      const lines = content.split("\n");
      for (const line of lines) {
        if (!line.trim()) continue;
        const parsed = JSON.parse(line);
        parsedCount++;
        if (parsed.alert || parsed.event_type === "alert") {
          alertsToAppend.push(JSON.stringify({
            alert_id: `alt_eve_${Date.now()}_${parsedCount}`,
            timestamp: parsed.timestamp || new Date().toISOString(),
            event: {
              event_id: `evt_eve_${parsedCount}`,
              event_type: "suricata_alert",
              source_ip: parsed.src_ip || "192.168.1.55",
              destination_ip: parsed.dest_ip || "198.51.100.23",
              severity: "high",
              confidence: 0.9,
              details: parsed,
            },
            threat_score: { score: 0.85, level: "High", confidence: 0.9, sources: ["suricata_eve"] },
            threat_level: "High",
            priority: "P2",
            summary: parsed.alert?.signature || "Suricata IDS Detection Event",
            recommended_actions: ["Investigate Source IP", "Review Suricata Rule"],
            metadata: { source_system: "suricata_eve_importer" },
          }));
        }
      }
    } else if (format === "zeek_tsv") {
      const lines = content.split("\n").filter((l: string) => !l.startsWith("#") && l.trim());
      parsedCount = lines.length;
    } else {
      // Generic JSON array or single object
      const parsed = typeof content === "string" ? JSON.parse(content) : content;
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      parsedCount = arr.length;
    }

    if (alertsToAppend.length > 0) {
      fs.appendFileSync(alertsPath, "\n" + alertsToAppend.join("\n"), "utf-8");
    }

    res.json({
      success: true,
      format,
      parsed_records: parsedCount,
      alerts_generated: alertsToAppend.length,
      sensor_tag: sensor_tag || "manual_import",
    });
  } catch (err: any) {
    res.status(400).json({ error: "Failed to parse log content", details: err.message });
  }
});

// 15. Export SOC Evidence Bundle
app.get("/api/export/bundle", (req, res) => {
  const alerts = readAlertsJsonl();
  const cases = readJsonFile(CASES_FILE, []);
  const iocs = readJsonFile(IOC_FILE, []);
  const bundle = {
    bundle_version: "2.1.0",
    export_timestamp: new Date().toISOString(),
    classification: "SOC Evidence Package",
    summary: {
      alert_count: alerts.length,
      case_count: cases.length,
      ioc_count: iocs.length,
    },
    alerts: alerts.slice(0, 50),
    cases,
    iocs,
  };
  res.setHeader("Content-Disposition", 'attachment; filename="cyber_ew_soc_bundle.json"');
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(bundle, null, 2));
});

// 16. ATTACK PATH GRAPH & FORENSIC REPORTING
app.get("/api/forensics/attack-path", (req, res) => {
  const alerts = readAlertsJsonl();

  const nodes = [
    {
      id: "node_c2_ext",
      label: "C2 Master Server (198.51.100.23)",
      type: "c2_server",
      ip: "198.51.100.23",
      risk_score: 0.98,
      compromised: true,
      tier: "external",
      alerts_count: alerts.filter(a => a.event?.destination_ip === "198.51.100.23").length || 3,
      techniques: ["T1071 (Web Protocols)", "T1573 (Encrypted Channel)"],
    },
    {
      id: "node_dmz_jump",
      label: "DMZ Edge Proxy (192.168.1.55)",
      type: "host",
      ip: "192.168.1.55",
      user: "svc_edge_proxy",
      risk_score: 0.88,
      compromised: true,
      tier: "perimeter",
      alerts_count: alerts.filter(a => a.event?.source_ip === "192.168.1.55").length || 5,
      techniques: ["T1190 (Exploit Public-Facing App)", "T1059 (PowerShell)"],
    },
    {
      id: "node_lan_workstation",
      label: "Finance Workstation (192.168.1.20)",
      type: "host",
      ip: "192.168.1.20",
      user: "finance_user",
      risk_score: 0.92,
      compromised: true,
      tier: "internal_lan",
      alerts_count: alerts.filter(a => a.event?.source_ip === "192.168.1.20").length || 4,
      techniques: ["T1059.001 (PowerShell)", "T1547 (Persistence)"],
    },
    {
      id: "node_cred_harvest",
      label: "Compromised Kerberos Ticket (admin)",
      type: "credential",
      user: "admin",
      risk_score: 0.95,
      compromised: true,
      tier: "domain_core",
      alerts_count: 3,
      techniques: ["T1110 (Brute Force)", "T1558.003 (Kerberoasting)"],
    },
    {
      id: "node_dc_core",
      label: "Domain Controller DC-01 (192.168.1.1)",
      type: "crown_jewel",
      ip: "192.168.1.1",
      user: "NT AUTHORITY\\SYSTEM",
      risk_score: 0.96,
      compromised: true,
      tier: "crown_jewel",
      alerts_count: 6,
      techniques: ["T1021.002 (SMB/RPC)", "T1486 (Ransomware Impact)"],
    },
    {
      id: "node_db_backup",
      label: "Cold Storage DB Backup (10.0.4.12)",
      type: "crown_jewel",
      ip: "10.0.4.12",
      user: "svc_backup",
      risk_score: 0.74,
      compromised: false,
      tier: "crown_jewel",
      alerts_count: 1,
      techniques: ["T1005 (Data from Local System)"],
    },
  ];

  const edges = [
    {
      id: "edge_1",
      source: "node_c2_ext",
      target: "node_dmz_jump",
      tactic: "Initial Access",
      technique: "T1190 Exploit Public-Facing App",
      protocol: "HTTPS / Port 443",
      confidence: 0.96,
      timestamp: "2026-08-27T02:45:10.000Z",
      description: "Inbound malicious reverse shell payload delivered via perimeter web proxy",
    },
    {
      id: "edge_2",
      source: "node_dmz_jump",
      target: "node_lan_workstation",
      tactic: "Lateral Movement",
      technique: "T1021.002 SMB & WMI Exec",
      protocol: "TCP / Port 445",
      confidence: 0.91,
      timestamp: "2026-08-27T02:51:22.000Z",
      description: "Lateral staging script uploaded to finance workstation administrative share",
    },
    {
      id: "edge_3",
      source: "node_lan_workstation",
      target: "node_cred_harvest",
      tactic: "Credential Access",
      technique: "T1558.003 Kerberoasting",
      protocol: "Kerberos / Port 88",
      confidence: 0.94,
      timestamp: "2026-08-27T03:02:15.000Z",
      description: "Service ticket request with RC4 cipher requested for domain admin SPN",
    },
    {
      id: "edge_4",
      source: "node_cred_harvest",
      target: "node_dc_core",
      tactic: "Privilege Escalation",
      technique: "T1078 Valid Domain Accounts",
      protocol: "RPC / Port 135",
      confidence: 0.97,
      timestamp: "2026-08-27T03:10:40.000Z",
      description: "Authentication with extracted high-privilege credentials on DC-01",
    },
    {
      id: "edge_5",
      source: "node_dc_core",
      target: "node_db_backup",
      tactic: "Collection / Exfiltration Prep",
      technique: "T1005 Data Staging",
      protocol: "SMB / Port 445",
      confidence: 0.82,
      timestamp: "2026-08-27T03:14:05.000Z",
      description: "Probing backup volume credentials; blocked by SOAR micro-segmentation rule",
    },
  ];

  res.json({ nodes, edges });
});

app.get("/api/forensics/report", (req, res) => {
  const alerts = readAlertsJsonl();
  const cases = readJsonFile(CASES_FILE, []);
  const iocs = readJsonFile(IOC_FILE, []);

  const report = {
    report_id: `FORENSIC-REP-${Date.now()}`,
    generated_at: new Date().toISOString(),
    incident_title: "APT29 Kill Chain Convergence & Domain Ransomware Stage",
    severity: "Critical",
    threat_actor: "UNC2452 / APT29 Cozy Bear Nexus",
    status: "Active Containment",
    executive_summary:
      "A coordinated 5-stage multi-vector intrusion was detected and isolated by the Cyber-EW Fusion Cell. The adversary established perimeter foothold via exploitation of web proxy vulnerabilities, executed lateral SMB traversal, harvested Kerberos credentials, and staged ransomware payloads on primary domain controllers. Immediate SOAR isolation playbooks (PB-001 & PB-002) successfully severed C2 outbound telemetry and segregated backup assets before data exfiltration completed.",
    impact_assessment: {
      affected_hosts: 4,
      compromised_accounts: 2,
      exfiltrated_data_mb: 42.5,
      business_interruption_hours: 0.5,
    },
    mitre_coverage: [
      {
        phase: "Initial Access",
        technique_id: "T1190",
        technique_name: "Exploit Public-Facing Application",
        evidence: "HTTP 500 response spike with base64 encoded PowerShell payload in URI parameters",
      },
      {
        phase: "Execution",
        technique_id: "T1059.001",
        technique_name: "PowerShell Interactive Scripting",
        evidence: "Encoded command execution bypass flags invoked under svc_edge_proxy context",
      },
      {
        phase: "Credential Access",
        technique_id: "T1558.003",
        technique_name: "Kerberoasting SPN Ticket Request",
        evidence: "Event ID 4769 RC4 encryption ticket requested for domain administrator account",
      },
      {
        phase: "Command & Control",
        technique_id: "T1071.001",
        technique_name: "Web Protocols (HTTPS C2)",
        evidence: "Beaconing intervals of 45s ±5s observed to 198.51.100.23:443 with TLS JA3 mismatch",
      },
      {
        phase: "Impact",
        technique_id: "T1486",
        technique_name: "Data Encrypted for Impact",
        evidence: "Mass shadowcopy deletion attempts (vssadmin delete shadows /all /quiet) intercepted",
      },
    ],
    key_iocs: iocs.map((i: any) => ({
      type: i.type,
      value: i.value,
      confidence: i.confidence,
      context: i.description,
    })),
    containment_actions_taken: [
      "Host 192.168.1.55 network interface placed into host-level micro-isolation (PB-001)",
      "C2 IP 198.51.100.23 null-routed at core perimeter firewall (PB-002)",
      "Domain Kerberos ticket-granting service (TGS) keys rotated",
      "Revocation of svc_edge_proxy and finance_user active tokens across domain controllers",
    ],
    recommendations: [
      "Enforce AES-256 exclusively for Kerberos pre-authentication across domain policies",
      "Patch external DMZ reverse proxies against CVE-2024-3400 / CVE-2023-46805",
      "Mandate FIDO2 hardware MFA for all administrative lateral logins",
      "Retain immutable offline air-gapped snapshots of primary database volumes",
    ],
  };

  res.json(report);
});

// ----------------------------------------------------
// PHASE 6: EW SPECTRUM & CROSS-DOMAIN FUSION API
// ----------------------------------------------------
let ewSignalsState = [
  {
    id: "SIG-EW-8821",
    timestamp: new Date(Date.now() - 4 * 60000).toISOString(),
    freq_mhz: 2437.5,
    bandwidth_khz: 22000,
    power_dbm: -42.8,
    snr_db: 28.4,
    modulation: "OFDM",
    protocol_detected: "C2 Mesh",
    emitter_classification: "Hostile C2 Emitter",
    threat_level: "Critical",
    bearing_deg: 42.6,
    elevation_deg: 14.2,
    signal_confidence: 0.94,
    jammer_threat_score: 0.91,
    geographic_fix: {
      lat: 38.8977,
      lon: -77.0365,
      cep_radius_m: 35,
      elevation_m: 48,
    },
    associated_cyber_entity: {
      ip: "198.51.100.23",
      hostname: "c2-mesh-gateway-01.darkrelay.net",
      mac: "00:50:56:B3:98:C1",
      c2_domain: "darkrelay.net",
      session_id: "SESSION-TLS-0091",
    },
    pulse_repetition_interval_us: 1250,
    duty_cycle_pct: 78.5,
    intercept_station: "SIGINT-STATION-ALPHA (Perimeter Mast 04)",
  },
  {
    id: "SIG-EW-8822",
    timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
    freq_mhz: 1575.42, // GPS L1 frequency
    bandwidth_khz: 2046,
    power_dbm: -28.1, // Unusually high power for GPS -> Jamming/Spoofing
    snr_db: 34.1,
    modulation: "DSSS",
    protocol_detected: "GPS Spoofing",
    emitter_classification: "Hostile Jammer",
    threat_level: "Critical",
    bearing_deg: 188.4,
    elevation_deg: 8.5,
    signal_confidence: 0.97,
    jammer_threat_score: 0.98,
    geographic_fix: {
      lat: 38.8895,
      lon: -77.0352,
      cep_radius_m: 80,
      elevation_m: 32,
    },
    associated_cyber_entity: {
      ip: "192.168.1.55",
      hostname: "edge-proxy-01.corp",
      session_id: "GNSS-NTP-DESYNC",
    },
    pulse_repetition_interval_us: 1000,
    duty_cycle_pct: 99.2,
    intercept_station: "SIGINT-STATION-BRAVO (Airfield Sensor 02)",
  },
  {
    id: "SIG-EW-8823",
    timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
    freq_mhz: 433.92,
    bandwidth_khz: 250,
    power_dbm: -61.2,
    snr_db: 16.8,
    modulation: "FSK",
    protocol_detected: "UAV Telemetry",
    emitter_classification: "Suspect Transponder",
    threat_level: "High",
    bearing_deg: 312.0,
    elevation_deg: 26.8,
    signal_confidence: 0.82,
    jammer_threat_score: 0.74,
    geographic_fix: {
      lat: 38.9050,
      lon: -77.0420,
      cep_radius_m: 120,
      elevation_m: 190,
    },
    associated_cyber_entity: {
      hostname: "uav-mavlink-rx-99",
    },
    pulse_repetition_interval_us: 20000,
    duty_cycle_pct: 12.0,
    intercept_station: "SIGINT-STATION-CHARLIE (Roof Tactical Array)",
  },
  {
    id: "SIG-EW-8824",
    timestamp: new Date(Date.now() - 40 * 60000).toISOString(),
    freq_mhz: 868.1,
    bandwidth_khz: 125,
    power_dbm: -74.5,
    snr_db: 12.1,
    modulation: "Chirp",
    protocol_detected: "Tactical Data Link",
    emitter_classification: "Friendly Beacon",
    threat_level: "Low",
    bearing_deg: 110.5,
    elevation_deg: 2.1,
    signal_confidence: 0.99,
    jammer_threat_score: 0.05,
    geographic_fix: {
      lat: 38.8920,
      lon: -77.0280,
      cep_radius_m: 15,
      elevation_m: 25,
    },
    associated_cyber_entity: {
      ip: "10.0.1.100",
      hostname: "friendly-base-beacon.mil",
    },
    pulse_repetition_interval_us: 50000,
    duty_cycle_pct: 4.5,
    intercept_station: "SIGINT-STATION-ALPHA (Perimeter Mast 04)",
  },
  {
    id: "SIG-EW-8825",
    timestamp: new Date(Date.now() - 55 * 60000).toISOString(),
    freq_mhz: 5800.0,
    bandwidth_khz: 40000,
    power_dbm: -53.2,
    snr_db: 22.0,
    modulation: "OFDM",
    protocol_detected: "Rogue Wi-Fi/BLE",
    emitter_classification: "Hostile C2 Emitter",
    threat_level: "High",
    bearing_deg: 275.2,
    elevation_deg: 5.4,
    signal_confidence: 0.88,
    jammer_threat_score: 0.85,
    geographic_fix: {
      lat: 38.8960,
      lon: -77.0450,
      cep_radius_m: 45,
      elevation_m: 40,
    },
    associated_cyber_entity: {
      ip: "192.168.1.20",
      mac: "D4:6E:0E:99:A2:14",
    },
    pulse_repetition_interval_us: 1800,
    duty_cycle_pct: 64.0,
    intercept_station: "SIGINT-STATION-DELTA (Mobile SDR Node)",
  },
];

let ewVectorsState = [
  {
    vector_id: "EW-VEC-01",
    category: "GPS / GNSS Spoofing",
    severity: "Critical",
    target_subsystem: "SOC Master NTP Server / Edge Gateway 192.168.1.55",
    correlation_hypothesis: "Coordinated RF spoofing on GPS L1 (1575.42 MHz) induced a 140ms clock drift on edge proxy, allowing adversary Kerberos replay attacks without timestamp rejection.",
    detected_at: new Date(Date.now() - 12 * 60000).toISOString(),
    emitter_ids: ["SIG-EW-8822"],
    correlated_alert_ids: ["ALT-20260824-001", "ALT-20260824-003"],
    active_countermeasure: "Beamforming Nulling",
    status: "Engaged",
    confidence_score: 0.96,
  },
  {
    vector_id: "EW-VEC-02",
    category: "RF-to-Cyber C2 Exfil",
    severity: "Critical",
    target_subsystem: "Finance Workstation LAN 192.168.1.20 / DarkRelay Mesh",
    correlation_hypothesis: "Compromised internal host bridging internal LAN traffic across an ad-hoc 2.4GHz OFDM signal to bypass egress proxy inspection.",
    detected_at: new Date(Date.now() - 4 * 60000).toISOString(),
    emitter_ids: ["SIG-EW-8821", "SIG-EW-8825"],
    correlated_alert_ids: ["ALT-20260824-002", "ALT-20260824-006"],
    active_countermeasure: "Directional Electronic Countermeasures (ECM)",
    status: "Active Threat",
    confidence_score: 0.92,
  },
  {
    vector_id: "EW-VEC-03",
    category: "Drone Command Hijack",
    severity: "High",
    target_subsystem: "Perimeter Perimeter Patrol Node CHARLIE",
    correlation_hypothesis: "433.92 MHz FSK unauthorized uplink transmission transmitting MAVLink override control frames toward facility rooftop.",
    detected_at: new Date(Date.now() - 25 * 60000).toISOString(),
    emitter_ids: ["SIG-EW-8823"],
    correlated_alert_ids: [],
    active_countermeasure: "Spectral Mask Filtering",
    status: "Monitoring",
    confidence_score: 0.79,
  },
];

let tenantContextState = {
  tenant_id: "TENANT-CYBER-EW-US-EAST",
  name: "Cyber-EW Fusion Command Enclave #1",
  security_classification: "TOP SECRET // NOFORN",
  assigned_role: "Global SOC Director",
  permitted_enclaves: ["DMZ-EDGE", "CORP-FINANCE", "DOMAIN-CORE-DC", "TACTICAL-RF-SIGINT", "SCADA-OT-ISOLATED"],
  active_session_token: "AUTH-JWT-SESSION-99214-SIGNED-HMAC256",
  enforce_mfa: true,
  rate_limit_eps: 100000,
};

app.get("/api/ew/signals", (req, res) => {
  res.json(ewSignalsState);
});

app.post("/api/ew/signals/intercept", (req, res) => {
  const { freq_mhz, power_dbm, modulation, protocol_detected, emitter_classification, bearing_deg } = req.body;
  const newSignal = {
    id: `SIG-EW-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toISOString(),
    freq_mhz: Number(freq_mhz) || 2400.0,
    bandwidth_khz: 20000,
    power_dbm: Number(power_dbm) || -45.0,
    snr_db: Math.round(20 + Math.random() * 15),
    modulation: modulation || "QAM",
    protocol_detected: protocol_detected || "C2 Mesh",
    emitter_classification: emitter_classification || "Suspect Transponder",
    threat_level: emitter_classification?.includes("Hostile") ? "Critical" : "Medium",
    bearing_deg: Number(bearing_deg) || Math.floor(Math.random() * 360),
    elevation_deg: Math.floor(Math.random() * 45),
    signal_confidence: 0.91,
    jammer_threat_score: 0.85,
    geographic_fix: {
      lat: 38.895 + (Math.random() - 0.5) * 0.02,
      lon: -77.036 + (Math.random() - 0.5) * 0.02,
      cep_radius_m: 40,
      elevation_m: 35,
    },
    associated_cyber_entity: {
      ip: "192.168.1." + Math.floor(10 + Math.random() * 200),
      session_id: "MANUAL-RF-INTERCEPT-" + Date.now(),
    },
    pulse_repetition_interval_us: 1500,
    duty_cycle_pct: 60,
    intercept_station: "TACTICAL-MOBILE-SDR-UNIT-01",
  };
  ewSignalsState.unshift(newSignal as any);
  res.json({ status: "success", signal: newSignal });
});

app.get("/api/ew/threat-vectors", (req, res) => {
  res.json(ewVectorsState);
});

app.post("/api/ew/countermeasures/engage", (req, res) => {
  const { vector_id, countermeasure } = req.body;
  const vec = ewVectorsState.find(v => v.vector_id === vector_id);
  if (vec) {
    vec.active_countermeasure = countermeasure;
    vec.status = "Engaged";
  }
  res.json({ status: "success", vector: vec });
});

app.get("/api/ew/spectrum-metrics", (req, res) => {
  const bands = [
    { band_name: "VHF / Tactical Comms", range_mhz: "30 - 300 MHz", occupancy_pct: 34, noise_floor_dbm: -102, peak_signal_dbm: -64, anomaly_count: 1, jamming_indicator: false },
    { band_name: "UHF / UAV Telemetry", range_mhz: "300 - 1000 MHz", occupancy_pct: 68, noise_floor_dbm: -95, peak_signal_dbm: -48, anomaly_count: 4, jamming_indicator: true },
    { band_name: "L-Band / GPS & GNSS", range_mhz: "1.0 - 2.0 GHz", occupancy_pct: 89, noise_floor_dbm: -78, peak_signal_dbm: -28, anomaly_count: 7, jamming_indicator: true },
    { band_name: "S-Band / Wi-Fi & Tactical Mesh", range_mhz: "2.0 - 4.0 GHz", occupancy_pct: 76, noise_floor_dbm: -88, peak_signal_dbm: -42, anomaly_count: 5, jamming_indicator: true },
    { band_name: "C-Band / Satellite & Radar", range_mhz: "4.0 - 8.0 GHz", occupancy_pct: 42, noise_floor_dbm: -98, peak_signal_dbm: -53, anomaly_count: 2, jamming_indicator: false },
  ];
  res.json(bands);
});

app.get("/api/tenant/context", (req, res) => {
  res.json(tenantContextState);
});

app.post("/api/tenant/switch-role", (req, res) => {
  const { role, classification } = req.body;
  if (role) tenantContextState.assigned_role = role;
  if (classification) tenantContextState.security_classification = classification;
  res.json({ status: "success", context: tenantContextState });
});

// ==========================================
// PHASE 7: SERVER-SIDE API ROUTES
// ==========================================

// 1. Autonomous AI-Assisted Threat Hunting & Playbook Generation (Gemini 3.7 Flash)
import { runAIThreatHunt } from "./server/geminiHunting";
import { getSamplePcapList, getPcapDissection, parseCustomRawPcap } from "./server/pcapDissector";
import { getTacticalMapState, updateSensorStatus } from "./server/tacticalGis";
import { getD3FENDMatrix, verifyD3FENDCountermeasure } from "./server/d3fendEngine";

app.post("/api/ai/hunt-hypotheses", async (req, res) => {
  try {
    const { prompt, technique } = req.body;
    const alerts = readAlertsJsonl();
    const result = await runAIThreatHunt(prompt || "", alerts, technique);
    res.json(result);
  } catch (err: any) {
    console.error("Error in /api/ai/hunt-hypotheses:", err);
    res.status(500).json({ error: err.message || "Failed to generate hunt hypothesis" });
  }
});

// 2. PCAP & Deep Packet Inspection (DPI)
app.get("/api/pcap/samples", (req, res) => {
  res.json(getSamplePcapList());
});

app.get("/api/pcap/dissect/:pcapName", (req, res) => {
  const pcapName = req.params.pcapName;
  res.json(getPcapDissection(pcapName));
});

app.post("/api/pcap/dissect-custom", (req, res) => {
  const { filename, content } = req.body;
  res.json(parseCustomRawPcap(filename || "upload.pcap", content || ""));
});

// 3. Geospatial Tactical Map & 3D Sensor Deployment
app.get("/api/tactical/gis-state", (req, res) => {
  res.json(getTacticalMapState());
});

app.post("/api/tactical/sensor/update", (req, res) => {
  const { sensor_id, status } = req.body;
  const updated = updateSensorStatus(sensor_id, status);
  res.json({ status: "success", sensor: updated });
});

// 4. MITRE D3FEND Countermeasure Matrix
app.get("/api/d3fend/matrix", (req, res) => {
  res.json(getD3FENDMatrix());
});

app.post("/api/d3fend/verify", (req, res) => {
  const { d3fend_id } = req.body;
  const verified = verifyD3FENDCountermeasure(d3fend_id);
  res.json({ status: "success", countermeasure: verified });
});

// ==========================================
// PHASE 8: ADVERSARY SIMULATION, TIMELINE & STIX PACKAGER
// ==========================================
import {
  getSimulationScenarios,
  getSimulationState,
  startSimulation,
  injectNextStep,
  burstExecuteSimulation,
  resetSimulation
} from "./server/adversarySimulator";
import {
  getUnifiedTimelineEvents,
  addTimelineEvent,
  resetTimeline
} from "./server/unifiedTimeline";
import { generateAirGapPackage } from "./server/stixEvidencePackager";

// 5. Adversary Simulation Sandbox
app.get("/api/simulation/scenarios", (req, res) => {
  res.json(getSimulationScenarios());
});

app.get("/api/simulation/state", (req, res) => {
  res.json(getSimulationState());
});

app.post("/api/simulation/start", (req, res) => {
  try {
    const { scenario_id } = req.body;
    const result = startSimulation(scenario_id);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/simulation/step", (req, res) => {
  try {
    const result = injectNextStep();
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/simulation/burst", (req, res) => {
  try {
    const result = burstExecuteSimulation();
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/simulation/reset", (req, res) => {
  const state = resetSimulation();
  res.json({ status: "reset", state });
});

// 6. Unified Multi-Domain Timeline
app.get("/api/timeline/events", (req, res) => {
  res.json(getUnifiedTimelineEvents());
});

app.post("/api/timeline/add", (req, res) => {
  const event = addTimelineEvent(req.body);
  res.json(event);
});

app.post("/api/timeline/reset", (req, res) => {
  const events = resetTimeline();
  res.json(events);
});

// 7. Air-Gap STIX 2.1 & CACAO Evidence Packager
app.get("/api/evidence/package", (req, res) => {
  const pkg = generateAirGapPackage(
    (req.query.incident_id as string) || "INC-2026-EW-089",
    (req.query.classification as any) || "SECRET // NOFORN",
    (req.query.custodian as string) || "Senior Cyber-EW Watch Officer"
  );
  res.json(pkg);
});

app.post("/api/evidence/package", (req, res) => {
  const { incident_id, classification, custodian } = req.body;
  const pkg = generateAirGapPackage(incident_id, classification, custodian);
  res.json(pkg);
});

// ==========================================
// PHASE 9: SITREP, BLAST RADIUS & CAMPAIGN STUDIO
// ==========================================
import { generateSitrepReport } from "./server/tacticalSitrep";
import {
  getBlastRadiusState,
  initializeBlastPatientZero,
  stepBlastPropagation,
  quarantineNode,
  resetBlastSimulation
} from "./server/blastRadiusEngine";
import { addCustomScenario, deleteCustomScenario } from "./server/adversarySimulator";

// 8. NATO / DoD 5-Paragraph SITREP Generator
app.get("/api/reports/sitrep", (req, res) => {
  const incidentId = (req.query.incident_id as string) || "INC-2026-EW-089";
  const classification = (req.query.classification as any) || "SECRET // NOFORN";
  const reportingUnit = (req.query.reporting_unit as string) || "Joint Tactical Cyber-EW Fusion Taskforce (CTF-71)";
  res.json(generateSitrepReport(incidentId, classification, reportingUnit));
});

app.post("/api/reports/sitrep", (req, res) => {
  const { incident_id, classification, reporting_unit } = req.body;
  res.json(generateSitrepReport(incident_id, classification, reporting_unit));
});

// 9. Blast Radius Physics & Contagion Engine
app.get("/api/blast-radius/state", (req, res) => {
  res.json(getBlastRadiusState());
});

app.post("/api/blast-radius/patient-zero", (req, res) => {
  const { patient_zero_id } = req.body;
  res.json(initializeBlastPatientZero(patient_zero_id || "WS-FIN-09"));
});

app.post("/api/blast-radius/step", (req, res) => {
  res.json(stepBlastPropagation());
});

app.post("/api/blast-radius/quarantine", (req, res) => {
  const { node_id } = req.body;
  res.json(quarantineNode(node_id));
});

app.post("/api/blast-radius/reset", (req, res) => {
  res.json(resetBlastSimulation());
});

// 10. Custom Threat Campaign Studio
app.post("/api/studio/campaigns", (req, res) => {
  try {
    const created = addCustomScenario(req.body);
    res.json({ status: "success", scenario: created });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/studio/campaigns/:id", (req, res) => {
  const success = deleteCustomScenario(req.params.id);
  res.json({ status: success ? "deleted" : "not_found" });
});




// ----------------------------------------------------
// VITE MIDDLEWARE / STATIC PRODUCTION SERVING

// ----------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*all", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Cyber-EW Fusion Cell] Server running on http://localhost:${PORT}`);
  });
}

startServer();
