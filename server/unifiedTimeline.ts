import { UnifiedTimelineEvent } from "../src/types";

const INITIAL_TIMELINE_EVENTS: UnifiedTimelineEvent[] = [
  {
    id: "tl-001",
    timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
    relative_offset_sec: 0,
    domain: "RF / SIGINT",
    event_type: "SPECTRAL_SWEEP_ANOMALY",
    severity: "MEDIUM",
    title: "Wideband RF Spectrum Sweep on 433 MHz Band",
    description: "Perimeter Mast Alpha detected unauthorized 2 MHz burst with high spectral occupancy and GFSK carrier.",
    source_entity: "Mast Alpha (37.7749, -122.4194)",
    target_entity: "Perimeter Sector North",
    mitre_ref: "T1595.002",
    telemetry_snippet: { frequency_mhz: 433.92, power_dbm: -42, snr_db: 18.5, bandwidth_khz: 200 },
    is_anomaly: true
  },
  {
    id: "tl-002",
    timestamp: new Date(Date.now() - 3600000 * 2.8).toISOString(),
    relative_offset_sec: 720,
    domain: "Tactical GIS",
    event_type: "SIGINT_AOA_BEARING_INTERSECT",
    severity: "HIGH",
    title: "Multi-Station AoA Triangulation Confirmed Emitter",
    description: "Mast Alpha (042.5°) and Roof Bravo (318.2°) calculated hostile emitter fix at MGRS 10SEG 0482 8912 with CEP 18m.",
    source_entity: "AoA Sensor Network",
    target_entity: "Hostile Mobile SDR Rover",
    mitre_ref: "T1046",
    telemetry_snippet: { lat: 37.7792, lon: -122.4140, cep_radius_m: 18, confidence: 0.94 },
    is_anomaly: true
  },
  {
    id: "tl-003",
    timestamp: new Date(Date.now() - 3600000 * 2.5).toISOString(),
    relative_offset_sec: 1800,
    domain: "Network DPI",
    event_type: "TLS_JA3_FINGERPRINT_MATCH",
    severity: "CRITICAL",
    title: "Cobalt Strike HTTPS C2 Handshake Flagged",
    description: "Outbound TLS Client Hello matched malicious JA3 hash 51c64c77e60f39ac3e97c803f8e4980e connecting to 198.51.100.89:443.",
    source_entity: "192.168.1.55 (Workstation-Fin02)",
    target_entity: "198.51.100.89:443",
    mitre_ref: "T1071.001",
    telemetry_snippet: { ja3: "51c64c77e60f39ac3e97c803f8e4980e", sni: "api.telemetry-sync-cloud.org", cipher_suite: "0xc02f" },
    is_anomaly: true,
    d3fend_id: "D3-JA3D",
    correlated_alert_id: "alert_c2_ja3_01"
  },
  {
    id: "tl-004",
    timestamp: new Date(Date.now() - 3600000 * 2.1).toISOString(),
    relative_offset_sec: 3240,
    domain: "Cyber Host",
    event_type: "KERBEROS_RC4_DOWNGRADE",
    severity: "CRITICAL",
    title: "Active Directory Kerberoasting Service Ticket Request",
    description: "Event ID 4769: Service Ticket requested for SPN MSSQLSvc/db01.corp using weak RC4-HMAC (0x17) encryption.",
    source_entity: "svc_backup (192.168.1.55)",
    target_entity: "DC01.corp.internal (10.0.0.1)",
    mitre_ref: "T1558.003",
    telemetry_snippet: { event_id: 4769, spn: "MSSQLSvc/db01.corp", encryption_type: "0x17", ticket_options: "0x40810000" },
    is_anomaly: true,
    d3fend_id: "D3-CH",
    correlated_alert_id: "alert_kerberoast_02"
  },
  {
    id: "tl-005",
    timestamp: new Date(Date.now() - 3600000 * 1.8).toISOString(),
    relative_offset_sec: 4320,
    domain: "Defense SOAR",
    event_type: "SOAR_DECOY_HONEY_TOKEN_TRIGGER",
    severity: "HIGH",
    title: "D3FEND Countermeasure: Decoy SPN Honey-Account Alert",
    description: "Deception countermeasure D3-HONEY triggered on fake SPN svc_sap_audit. Identity isolation rule executed.",
    source_entity: "SOAR Defensive Engine",
    target_entity: "192.168.1.55",
    mitre_ref: "T1558.003",
    telemetry_snippet: { d3fend_id: "D3-HONEY", action: "Account Lockout + NetFlow Isolation", response_time_ms: 120 },
    is_anomaly: false,
    d3fend_id: "D3-HONEY"
  },
  {
    id: "tl-006",
    timestamp: new Date(Date.now() - 3600000 * 1.3).toISOString(),
    relative_offset_sec: 6120,
    domain: "Tactical GIS",
    event_type: "GPS_L1_SPOOF_BUBBLE_DETECT",
    severity: "CRITICAL",
    title: "GPS L1 Time-Sync Spoofing Degradation Zone Active",
    description: "Substation 14 GPS receivers detected 1240ms clock jitter and false ephemeris PRN signals.",
    source_entity: "Hostile Jammer (37.7780, -122.4150)",
    target_entity: "Substation 14 SCADA RTU",
    mitre_ref: "T1498.001",
    telemetry_snippet: { band: "1575.42 MHz", j_s_ratio_db: 18.2, drift_ms: 1240, radius_m: 650 },
    is_anomaly: true,
    d3fend_id: "D3-GPSA"
  },
  {
    id: "tl-007",
    timestamp: new Date(Date.now() - 3600000 * 0.9).toISOString(),
    relative_offset_sec: 7560,
    domain: "Network DPI",
    event_type: "MODBUS_SCADA_UNAUTHORIZED_WRITE",
    severity: "CRITICAL",
    title: "Modbus TCP Coil Force Command Injected to Feeder 03",
    description: "Function code 0x05 (Force Single Coil) sent to UnitID 0x01 without valid operator authentication token.",
    source_entity: "10.200.4.15 (Infiltrated Jump Host)",
    target_entity: "192.168.10.14:502 (Substation 14 RTU)",
    mitre_ref: "T0855",
    telemetry_snippet: { unit_id: 1, function_code: 5, address: "0x0014", data: "0xFF00", protocol: "MODBUS/TCP" },
    is_anomaly: true,
    d3fend_id: "D3-PRC",
    correlated_alert_id: "alert_modbus_trip_03"
  },
  {
    id: "tl-008",
    timestamp: new Date(Date.now() - 3600000 * 0.4).toISOString(),
    relative_offset_sec: 9360,
    domain: "Cyber Host",
    event_type: "DNS_TUNNEL_EXFILTRATION",
    severity: "HIGH",
    title: "High-Entropy DNS Tunneling Data Exfiltration",
    description: "Shannon entropy 4.82 bits/symbol detected on subdomains querying ns1.tunnel-dns-c2.net.",
    source_entity: "192.168.1.55",
    target_entity: "ns1.tunnel-dns-c2.net",
    mitre_ref: "T1071.004",
    telemetry_snippet: { entropy: 4.82, query_count: 840, bytes_exfiltrated: 48900 },
    is_anomaly: true,
    d3fend_id: "D3-DNF"
  },
  {
    id: "tl-009",
    timestamp: new Date(Date.now() - 3600000 * 0.1).toISOString(),
    relative_offset_sec: 10440,
    domain: "Defense SOAR",
    event_type: "EDR_HOST_CONTAINMENT_EXECUTED",
    severity: "INFO",
    title: "Autonomous Host Isolation & Firewall Blacklist Active",
    description: "Endpoint 192.168.1.55 isolated from internal LAN; perimeter firewall dropped all egress to 198.51.100.89.",
    source_entity: "Cyber-EW Fusion SOAR Engine",
    target_entity: "192.168.1.55 / 198.51.100.89",
    mitre_ref: "M1037",
    telemetry_snippet: { status: "Enforced", action_count: 3, isolation_latency_ms: 84 },
    is_anomaly: false,
    d3fend_id: "D3-IA"
  }
];

let dynamicTimeline: UnifiedTimelineEvent[] = [...INITIAL_TIMELINE_EVENTS];

export function getUnifiedTimelineEvents(): UnifiedTimelineEvent[] {
  return dynamicTimeline.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

export function addTimelineEvent(event: Omit<UnifiedTimelineEvent, "id">): UnifiedTimelineEvent {
  const newEv: UnifiedTimelineEvent = {
    ...event,
    id: `tl-${Date.now()}-${Math.floor(Math.random() * 1000)}`
  };
  dynamicTimeline.push(newEv);
  return newEv;
}

export function resetTimeline(): UnifiedTimelineEvent[] {
  dynamicTimeline = [...INITIAL_TIMELINE_EVENTS];
  return dynamicTimeline;
}
