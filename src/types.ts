export interface NormalizedEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_host?: string | null;
  destination_host?: string | null;
  username?: string | null;
  process_name?: string | null;
  file_path?: string | null;
  url?: string | null;
  port?: number | null;
  protocol?: string | null;
  bytes_sent?: number | null;
  bytes_received?: number | null;
  severity: string;
  confidence: number;
  details: Record<string, any>;
  source_id?: string;
  tags?: string[];
  is_external?: boolean;
}

export interface AlertRecord {
  alert_id: string;
  timestamp: string;
  event: NormalizedEvent;
  threat_score: {
    score: number;
    level: string;
    confidence: number;
    sources: string[];
    details: Record<string, any>;
  };
  threat_level: string;
  priority: string;
  summary: string;
  recommended_actions: string[];
  metadata: {
    correlation_present?: boolean;
    behavior_analysis_present?: boolean;
    source_system?: string;
    dedupe_key?: string;
    [key: string]: any;
  };
  correlation?: {
    cluster_count: number;
    clusters: Array<{
      cluster_id: string;
      correlation_type: string;
      confidence: number;
      event_count: number;
      entities: Record<string, string[]>;
    }>;
  };
  behavior_analysis?: {
    pattern_count: number;
    patterns: Array<{
      pattern_type: string;
      confidence: number;
      description: string;
    }>;
  };
  // UI extended state
  status?: string;
  notes?: string;
  score?: number;
  level?: string;
  patterns?: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  file_path?: string | null;
  event_type?: string;
  event_id?: string;
  details?: Record<string, any>;
}

export interface CaseRecord {
  case_id: string;
  alert_id: string;
  title: string;
  status: "New" | "Investigating" | "Contained" | "False Positive" | "Closed";
  owner: string;
  disposition: "Undetermined" | "True Positive" | "False Positive" | "Benign" | "Duplicate";
  playbook: string;
  notes: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  alert_snapshot: any;
}

export interface IOCRecord {
  value: string;
  ioc_type: "ip" | "domain" | "hash" | "user" | "url";
  threat_type: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  description: string;
  tags: string[];
}

export interface AttackTimelineEntry {
  event_id: string;
  timestamp: string;
  tactic: string;
  technique_id: string;
  technique: string;
  phase: number;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  process_name?: string;
  file_path?: string;
  score: number;
  level: string;
  evidence: string;
  summary?: string;
}

export interface InvestigationReport {
  generated_at: string;
  scope: string;
  summary: {
    timeline_events: number;
    tactics: Record<string, number>;
    techniques: Record<string, number>;
    entities: string[];
    first_seen: string | null;
    last_seen: string | null;
  };
  timeline: AttackTimelineEntry[];
}

export interface Playbook {
  playbook_id: string;
  name: string;
  category: string;
  description: string;
  trigger: string;
  actions: Array<{
    action: string;
    target: string;
    parameters?: Record<string, any>;
    destructive?: boolean;
  }>;
}

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  timestamp: string;
  actor: string;
  approved: boolean;
  status: string;
  actions_executed: Array<{
    action: string;
    target: string;
    status: string;
    output?: any;
  }>;
}

export interface PipelineStats {
  events_processed: number;
  alerts_generated: number;
  threat_intel_matches: number;
  ml_anomalies_detected: number;
  signature_matches: number;
  start_time: string;
  uptime: number;
  processing_rate: number;
  queue_status: {
    raw_events: number;
    normalized_events: number;
    correlated_events: number;
    analyzed_events: number;
    scored_events: number;
  };
  engine_stats?: Record<string, any>;
}

export interface CapabilityItem {
  capability: string;
  benchmark: string;
  local: string;
  status: "Active" | "Partial" | "Demo";
}

export interface ConnectorItem {
  name: string;
  type: string;
  status: "Ready" | "Config Needed" | "Demo/Blueprint" | "Active";
  format: string;
  description: string;
  enterprise_ready: boolean;
}

export interface ClusterWorker {
  worker_id: string;
  name: string;
  role: "ingestion" | "normalization" | "correlation" | "ml_analytics" | "scoring";
  status: "active" | "idle" | "congested" | "offline";
  eps_current: number;
  eps_peak: number;
  cpu_usage_pct: number;
  memory_mb: number;
  buffer_depth: number;
  buffer_capacity: number;
  processed_total: number;
  dropped_events: number;
  latency_ms: number;
  last_heartbeat: string;
}

export interface IngestStreamStatus {
  is_streaming: boolean;
  target_eps: number;
  actual_eps: number;
  total_streamed: number;
  active_scenario: string;
  backpressure_active: boolean;
  drop_rate_pct: number;
  avg_pipeline_latency_ms: number;
  p99_latency_ms: number;
  workers: ClusterWorker[];
}

export interface StressTestScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  target_eps: number;
  duration_sec: number;
  distribution: {
    suricata_eve_pct: number;
    zeek_tsv_pct: number;
    windows_sysmon_pct: number;
    pcap_raw_pct: number;
    syslog_auth_pct: number;
  };
  attack_injection_rate: number;
}

export interface AttackPathNode {
  id: string;
  label: string;
  type: "host" | "user" | "c2_server" | "process" | "compromised_asset" | "credential" | "crown_jewel";
  ip?: string;
  user?: string;
  risk_score: number;
  compromised: boolean;
  tier: "external" | "perimeter" | "internal_lan" | "domain_core" | "crown_jewel";
  alerts_count: number;
  techniques: string[];
}

export interface AttackPathEdge {
  id: string;
  source: string;
  target: string;
  tactic: string;
  technique: string;
  protocol?: string;
  confidence: number;
  timestamp: string;
  description: string;
}

export interface ForensicReport {
  report_id: string;
  generated_at: string;
  incident_title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  threat_actor: string;
  status: "Active Containment" | "Remediated" | "Under Investigation";
  executive_summary: string;
  impact_assessment: {
    affected_hosts: number;
    compromised_accounts: number;
    exfiltrated_data_mb: number;
    business_interruption_hours: number;
  };
  mitre_coverage: Array<{
    phase: string;
    technique_id: string;
    technique_name: string;
    evidence: string;
  }>;
  key_iocs: Array<{
    type: string;
    value: string;
    confidence: number;
    context: string;
  }>;
  containment_actions_taken: string[];
  recommendations: string[];
}

// ==========================================
// PHASE 6: ADVANCED EW SPECTRUM & CROSS-DOMAIN FUSION
// ==========================================

export interface RFEmissionSignal {
  id: string;
  timestamp: string;
  freq_mhz: number;
  bandwidth_khz: number;
  power_dbm: number;
  snr_db: number;
  modulation: "FSK" | "PSK" | "QAM" | "FHSS" | "DSSS" | "OFDM" | "CW" | "Chirp" | "Custom";
  protocol_detected: "Tactical Data Link" | "UAV Telemetry" | "SATCOM Uplink" | "C2 Mesh" | "Rogue Wi-Fi/BLE" | "Radar Chirp" | "GPS Spoofing" | "Unknown";
  emitter_classification: "Hostile Jammer" | "Hostile C2 Emitter" | "Friendly Beacon" | "Civilian / Commercial" | "Suspect Transponder" | "Unclassified";
  threat_level: "Critical" | "High" | "Medium" | "Low" | "Benign";
  bearing_deg: number;
  elevation_deg: number;
  signal_confidence: number;
  jammer_threat_score: number;
  geographic_fix: {
    lat: number;
    lon: number;
    cep_radius_m: number; // Circular Error Probable in meters
    elevation_m: number;
  };
  associated_cyber_entity?: {
    ip?: string;
    hostname?: string;
    mac?: string;
    c2_domain?: string;
    session_id?: string;
  };
  pulse_repetition_interval_us: number;
  duty_cycle_pct: number;
  intercept_station: string;
}

export interface EWThreatVector {
  vector_id: string;
  category: "RF Jamming" | "GPS / GNSS Spoofing" | "RF-to-Cyber C2 Exfil" | "Tactical RF Insertion" | "EW Radar Intercept" | "Drone Command Hijack";
  severity: "Critical" | "High" | "Medium" | "Low";
  target_subsystem: string;
  correlation_hypothesis: string;
  detected_at: string;
  emitter_ids: string[];
  correlated_alert_ids: string[];
  active_countermeasure: "Directional Electronic Countermeasures (ECM)" | "Adaptive Frequency Hopping" | "Beamforming Nulling" | "RF Port Isolation" | "Spectral Mask Filtering" | "None Active";
  status: "Engaged" | "Active Threat" | "Mitigated" | "Monitoring";
  confidence_score: number;
}

export interface SpectrumBandMetrics {
  band_name: string;
  range_mhz: string;
  occupancy_pct: number;
  noise_floor_dbm: number;
  peak_signal_dbm: number;
  anomaly_count: number;
  jamming_indicator: boolean;
}

export interface TenantContext {
  tenant_id: string;
  name: string;
  security_classification: "UNCLASSIFIED" | "CONFIDENTIAL" | "SECRET" | "TOP SECRET // NOFORN";
  assigned_role: "Global SOC Director" | "Senior Tier-3 Hunter" | "EW Specialist Operator" | "SOC Analyst" | "Auditor / Read-Only";
  permitted_enclaves: string[];
  active_session_token: string;
  enforce_mfa: boolean;
  rate_limit_eps: number;
}

// ==========================================
// PHASE 7: AUTONOMOUS AI HUNTING & PLAYBOOK GENERATION
// ==========================================

export interface AIHuntingHypothesis {
  hypothesis_id: string;
  title: string;
  objective: string;
  targeted_technique: string;
  confidence: number;
  data_sources_required: string[];
  detection_logic_query: string;
  rationale: string;
}

export interface GeneratedSigmaRule {
  title: string;
  id: string;
  status: "experimental" | "test" | "production";
  description: string;
  author: string;
  date: string;
  references: string[];
  tags: string[];
  logsource: {
    category?: string;
    product: string;
    service?: string;
  };
  detection: {
    selection?: Record<string, any>;
    filter?: Record<string, any>;
    condition: string;
    [key: string]: any;
  };
  falsepositives: string[];
  level: "low" | "medium" | "high" | "critical";
  raw_yaml: string;
}

export interface GeneratedYaraRule {
  rule_name: string;
  description: string;
  author: string;
  threat_actor?: string;
  strings: { identifier: string; value: string; type: "text" | "hex" | "regex" }[];
  condition: string;
  raw_yara: string;
}

export interface GeneratedPlaybook {
  playbook_id: string;
  name: string;
  trigger_event: string;
  mitre_technique: string;
  confidence_threshold: number;
  steps: {
    step_num: number;
    action_type: "Network Isolation" | "Process Termination" | "Credential Revocation" | "Forensic Snapshot" | "ECM Jamming Null" | "SOAR Notification";
    target: string;
    requires_approval: boolean;
    automated_fallback: string;
  }[];
  rollback_procedure: string;
  raw_yaml: string;
}

export interface AIHuntingResponse {
  hypothesis: AIHuntingHypothesis;
  sigma_rule: GeneratedSigmaRule;
  yara_rule: GeneratedYaraRule;
  playbook: GeneratedPlaybook;
  threat_intel_summary: string;
  source: "Gemini 3.7 Flash Live" | "Autonomous Cyber-EW Fusion Engine";
}

// ==========================================
// PHASE 7: PCAP & DEEP PACKET INSPECTION (DPI)
// ==========================================

export interface PCAPPacket {
  frame_number: number;
  timestamp: string;
  time_relative_s: number;
  source_mac: string;
  dest_mac: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: "TLSv1.3" | "TLSv1.2" | "DNS" | "HTTP/1.1" | "HTTP/2" | "Kerberos" | "TCP" | "UDP" | "ICMP" | "SMB2" | "Custom C2";
  length_bytes: number;
  info: string;
  flags?: string[];
  payload_preview?: string;
  hex_dump?: string;
  is_anomalous: boolean;
  dpi_findings?: {
    ja3_hash?: string;
    ja4_hash?: string;
    sni_server_name?: string;
    dns_query_name?: string;
    dns_query_type?: string;
    dns_entropy?: number;
    http_method?: string;
    http_uri?: string;
    http_user_agent?: string;
    cobalt_strike_watermark?: string;
    entropy_score?: number;
  };
}

export interface PCAPSessionFlow {
  flow_id: string;
  source_endpoint: string;
  dest_endpoint: string;
  protocol: string;
  packet_count: number;
  byte_count: number;
  start_time: string;
  duration_ms: number;
  anomaly_flag: string;
  ja3_fingerprint?: string;
  app_layer_proto: string;
}

export interface PCAPDissectionResult {
  pcap_name: string;
  capture_time: string;
  total_packets: number;
  total_bytes: number;
  duration_seconds: number;
  anomalous_packets_count: number;
  detected_threats: string[];
  packets: PCAPPacket[];
  flows: PCAPSessionFlow[];
  dpi_summary: {
    tls_sessions: number;
    dns_tunnels_flagged: number;
    cleartext_credentials: number;
    suspicious_ja3_hashes: string[];
  };
}

// ==========================================
// PHASE 7: GEOSPATIAL TACTICAL MAP & 3D SENSORS
// ==========================================

export interface TacticalSensorStation {
  id: string;
  name: string;
  callsign: string;
  type: "Fixed SIGINT Mast" | "Mobile SDR Patrol" | "Airfield Radar" | "Roof Array" | "SATCOM Ground Node";
  lat: number;
  lon: number;
  elevation_m: number;
  coverage_radius_km: number;
  frequency_band: string;
  status: "Active Tracking" | "Calibrating" | "Standby" | "ECM Active";
  bearing_coverage_arc: [number, number]; // e.g. [0, 360]
  health_pct: number;
}

export interface TacticalCyberAsset {
  id: string;
  name: string;
  role: "Domain Controller" | "DMZ Gateway" | "Finance Subnet" | "SCADA Substation" | "C2 Node (Hostile)" | "Backup Vault";
  lat: number;
  lon: number;
  ip: string;
  threat_level: "Critical" | "High" | "Medium" | "Low" | "Nominal";
  compromise_status: "Compromised" | "Targeted" | "Secure" | "Isolated";
}

export interface JammingContourZone {
  id: string;
  name: string;
  center_lat: number;
  center_lon: number;
  radius_m: number;
  band_affected: "GPS L1 (1575.42 MHz)" | "Wi-Fi 2.4 GHz" | "UAV 433 MHz" | "SATCOM C-Band";
  interference_dbm: number;
  severity: "Severe Jamming" | "Moderate Degradation" | "Low Interference";
}

export interface TacticalMapState {
  map_center: [number, number];
  zoom_level: number;
  sensors: TacticalSensorStation[];
  cyber_assets: TacticalCyberAsset[];
  jamming_zones: JammingContourZone[];
  active_bearing_lines: {
    station_id: string;
    bearing_deg: number;
    target_signal_id: string;
    is_hostile: boolean;
  }[];
}

// ==========================================
// PHASE 7: MITRE D3FEND DEFENSIVE MATRIX
// ==========================================

export type D3FENDPillar = "Model" | "Harden" | "Detect" | "Isolate" | "Deceive" | "Evict";

export interface D3FENDCountermeasure {
  d3fend_id: string;
  d3fend_name: string;
  pillar: D3FENDPillar;
  description: string;
  mitre_attack_countered: {
    technique_id: string;
    technique_name: string;
  }[];
  operational_status: "Active & Enforcing" | "Partially Deployed" | "Planned / Gap" | "Automated via SOAR";
  defensive_artifact: string;
  verification_test: string;
  last_verified_at: string;
  confidence_pct: number;
}

export interface D3FENDMatrixOverview {
  total_countermeasures: number;
  active_enforced_count: number;
  coverage_percentage: number;
  pillars: {
    pillar: D3FENDPillar;
    countermeasures: D3FENDCountermeasure[];
  }[];
}

// ==========================================
// PHASE 8: ADVERSARY SIMULATION SANDBOX
// ==========================================

export interface SimulationStep {
  step_number: number;
  name: string;
  domain: "Cyber" | "RF / Electronic Warfare" | "Physical / GIS" | "Network / DPI";
  mitre_technique: string;
  technique_name: string;
  description: string;
  artifact_payload: string;
  expected_alert: string;
  d3fend_countermeasure_id?: string;
  status: "Pending" | "Injected" | "Blocked" | "Detected";
  injected_at?: string;
}

export interface AdversaryScenario {
  id: string;
  title: string;
  threat_actor: string;
  target_sector: string;
  severity: "Critical" | "High" | "Medium";
  category: "SCADA / Grid Blackout" | "Stealth C2 & Active Directory" | "Tactical Drone EW Incursion" | "Destructive Wiper & Financial";
  summary: string;
  complexity: "Advanced Multi-Stage" | "High-Velocity Burst" | "Low & Slow Tactical";
  estimated_duration_sec: number;
  steps: SimulationStep[];
  iocs_involved: {
    ips: string[];
    domains: string[];
    hashes: string[];
    rf_frequencies: string[];
  };
}

export interface SimulationState {
  active_scenario_id: string | null;
  status: "Idle" | "Running" | "Paused" | "Completed";
  current_step_index: number;
  total_steps: number;
  elapsed_sec: number;
  events_generated: number;
  alerts_fired: number;
  d3fend_blocks_triggered: number;
  logs: {
    timestamp: string;
    level: "INFO" | "WARN" | "ALERT" | "DEFENSE";
    message: string;
    step_number: number;
  }[];
}

// ==========================================
// PHASE 8: UNIFIED TIMELINE & CROSS-DOMAIN SCRUBBER
// ==========================================

export type TimelineDomain = "Cyber Host" | "RF / SIGINT" | "Tactical GIS" | "Network DPI" | "Defense SOAR";

export interface UnifiedTimelineEvent {
  id: string;
  timestamp: string;
  relative_offset_sec: number;
  domain: TimelineDomain;
  event_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  source_entity: string;
  target_entity: string;
  mitre_ref?: string;
  telemetry_snippet: Record<string, any>;
  is_anomaly: boolean;
  d3fend_id?: string;
  correlated_alert_id?: string;
}

export interface TimelinePlaybackState {
  is_playing: boolean;
  playback_speed: 0.5 | 1 | 2 | 5 | 10;
  current_time_offset: number;
  max_duration_sec: number;
  active_domain_filter: TimelineDomain | "All";
  selected_event_id: string | null;
}

// ==========================================
// PHASE 8: AIR-GAP STIX 2.1 & CACAO EVIDENCE PACKAGER
// ==========================================

export interface STIXObject {
  type: string;
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  name?: string;
  description?: string;
  labels?: string[];
  confidence?: number;
  pattern?: string;
  pattern_type?: string;
  valid_from?: string;
  source_ref?: string;
  target_ref?: string;
  relationship_type?: string;
  [key: string]: any;
}

export interface STIXBundle {
  type: "bundle";
  id: string;
  spec_version: "2.1";
  objects: STIXObject[];
}

export interface CACAOAction {
  type: "action";
  name: string;
  description: string;
  action_type: "investigate" | "mitigate" | "isolate" | "remediate";
  commands: {
    type: "bash" | "powershell" | "snort" | "sigma" | "soar";
    command: string;
  }[];
}

export interface CACAOPlaybook {
  type: "playbook";
  spec_version: "cacao-2.0";
  id: string;
  name: string;
  description: string;
  playbook_types: string[];
  workflow_start: string;
  workflow: Record<string, CACAOAction>;
}

export interface ForensicEvidenceManifest {
  manifest_id: string;
  generated_at: string;
  generated_by: string;
  security_classification: "UNCLASSIFIED" | "SECRET // NOFORN" | "TOP SECRET // SCI // TK";
  custody_chain: {
    custodian: string;
    role: string;
    organization: string;
    timestamp: string;
    signature_algorithm: string;
    digital_signature: string;
  }[];
  artifacts: {
    filename: string;
    file_type: "PCAP" | "STIX 2.1 Bundle" | "CACAO Playbook" | "Sigma Rule" | "Forensic Memory Slice";
    size_bytes: number;
    sha256: string;
    sha512: string;
    description: string;
  }[];
  integrity_verification: {
    hash_tree_root: string;
    is_airgap_sealed: boolean;
    verification_status: "Verified Authentic" | "Tampered" | "Pending Seal";
  };
}

export interface AirGapEvidencePackage {
  package_id: string;
  incident_id: string;
  title: string;
  classification: string;
  stix_bundle: STIXBundle;
  cacao_playbook: CACAOPlaybook;
  manifest: ForensicEvidenceManifest;
  raw_sigma_rules: string[];
  pcap_summary: {
    packets_included: number;
    ja3_hashes: string[];
    flows_reconstructed: number;
  };
}

// ==========================================
// PHASE 9: TACTICAL RADIO AUDIO DEMODULATOR & DSP
// ==========================================

export type RadioDemodMode = "NFM (Voice)" | "WFM (Broadcast)" | "AM (Airband)" | "CW (Morse Code)" | "AFSK / APRS (Data)" | "FHSS (Frequency Hop)";

export interface DemodulatedSignalProfile {
  signal_id: string;
  freq_mhz: number;
  mode: RadioDemodMode;
  bandwidth_khz: number;
  snr_db: number;
  rssi_dbm: number;
  callsign?: string;
  audio_tone_hz?: number;
  squelch_open: boolean;
  raw_transcript?: string;
  morse_text?: string;
  data_payload_hex?: string;
}

// ==========================================
// PHASE 9: NATO / DOD 5-PARAGRAPH SITREP GENERATOR
// ==========================================

export interface SitrepSection {
  title: string;
  paragraph_number: "1. SITUATION" | "2. MISSION" | "3. EXECUTION" | "4. ADMINISTRATION & LOGISTICS" | "5. COMMAND & SIGNAL";
  subsections: {
    subtitle: string;
    content: string;
    key_bullet_points?: string[];
  }[];
}

export interface SitrepDamageAssessment {
  compromised_endpoints_count: number;
  active_directory_domain_risk: "CRITICAL" | "HIGH" | "ELEVATED" | "NOMINAL";
  scada_substation_status: "DEGRADED" | "TRIPPED" | "ISOLATED" | "SECURE";
  grid_capacity_impact_mw: number;
  financial_impact_est_usd: number;
  rto_hours: number;
  threat_containment_pct: number;
  pcap_exfil_bytes: number;
}

export interface TacticalSitrepReport {
  report_id: string;
  generated_at: string;
  dtg_military_timestamp: string;
  classification: "UNCLASSIFIED" | "SECRET // NOFORN" | "TOP SECRET // SCI // TK";
  operation_codename: string;
  reporting_unit: string;
  incident_id: string;
  threat_actor: string;
  executive_summary: string;
  damage_assessment: SitrepDamageAssessment;
  sections: SitrepSection[];
  active_mitre_techniques: string[];
  active_d3fend_countermeasures: string[];
}

// ==========================================
// PHASE 9: BLAST RADIUS & CONTAGION PHYSICS GRAPH
// ==========================================

export type BlastNodeType = "workstation" | "domain_controller" | "scada_plc" | "cloud_iam" | "database" | "rf_sensor" | "c2_beacon";

export interface BlastRadiusNode {
  id: string;
  label: string;
  type: BlastNodeType;
  zone: "Corporate IT" | "Active Directory" | "OT / SCADA Enclave" | "AWS / Cloud" | "Tactical EW";
  criticality: "Crown Jewel" | "High" | "Medium" | "Low";
  status: "Clean" | "Patient Zero" | "Infected" | "Quarantined" | "Recovered";
  ip?: string;
  operating_system?: string;
  vulnerability?: string;
  financial_value_usd: number;
  power_draw_mw?: number;
  infection_step?: number;
  infection_vector?: string;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
}

export interface BlastRadiusEdge {
  id: string;
  source: string | any;
  target: string | any;
  protocol: "SMB / RPC" | "Modbus / IEC-104" | "Kerberos RC4" | "AWS IAM AssumeRole" | "RF Burst 433MHz" | "HTTPS C2";
  is_compromised_path: boolean;
  blocked_by_d3fend?: boolean;
}

export interface BlastRadiusState {
  nodes: BlastRadiusNode[];
  edges: BlastRadiusEdge[];
  patient_zero_id: string;
  simulation_step: number;
  is_propagating: boolean;
  total_loss_usd: number;
  total_mw_lost: number;
  compromised_nodes_count: number;
  quarantined_nodes_count: number;
  propagation_log: {
    step: number;
    timestamp: string;
    from_node: string;
    to_node: string;
    protocol: string;
    vector: string;
  }[];
}

// ==========================================
// PHASE 9: CUSTOM THREAT CAMPAIGN STUDIO
// ==========================================

export interface CustomCampaignDraft {
  id: string;
  title: string;
  threat_actor: string;
  target_sector: string;
  severity: "Critical" | "High" | "Medium";
  category: "SCADA / Grid Blackout" | "Stealth C2 & Active Directory" | "Tactical Drone EW Incursion" | "Destructive Wiper & Financial";
  summary: string;
  complexity: "Advanced Multi-Stage" | "High-Velocity Burst" | "Low & Slow Tactical";
  estimated_duration_sec: number;
  steps: SimulationStep[];
  iocs_involved: {
    ips: string[];
    domains: string[];
    hashes: string[];
    rf_frequencies: string[];
  };
  author: string;
  created_at: string;
}



