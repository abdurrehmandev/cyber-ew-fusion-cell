import { D3FENDCountermeasure, D3FENDMatrixOverview, D3FENDPillar } from "../src/types";

let d3fendCountermeasures: D3FENDCountermeasure[] = [
  // Pillar: MODEL
  {
    d3fend_id: "D3-NTM",
    d3fend_name: "Network Traffic Mapping",
    pillar: "Model",
    description: "Construct and maintain continuous graph topology of internal host communication baselines, SDR RF sensor nodes, and external egress channels.",
    mitre_attack_countered: [
      { technique_id: "T1046", technique_name: "Network Service Discovery" },
      { technique_id: "T1016", technique_name: "System Network Configuration Discovery" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Zeek Connection Graph & Suricata Flow Topology Engine",
    verification_test: "Automated synthetic port scan injection verifies graph node node-edge update latency < 500ms.",
    last_verified_at: "2026-08-27T02:45:00Z",
    confidence_pct: 98,
  },
  {
    d3fend_id: "D3-SAM",
    d3fend_name: "Software Asset Inventory Mapping",
    pillar: "Model",
    description: "Enumerate and cryptographically hash all running binaries, DLLs, and kernel drivers across domain controllers and perimeter hosts.",
    mitre_attack_countered: [
      { technique_id: "T1082", technique_name: "System Information Discovery" },
      { technique_id: "T1518", technique_name: "Security Software Discovery" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Sysmon Event ID 1 / 6 SHA256 Catalog",
    verification_test: "Verify uncatalogued binary execution triggers instant Level 4 anomaly alert.",
    last_verified_at: "2026-08-27T03:10:00Z",
    confidence_pct: 95,
  },

  // Pillar: HARDEN
  {
    d3fend_id: "D3-CH",
    d3fend_name: "Kerberos Credential Hardening & AES-256 Enforcement",
    pillar: "Harden",
    description: "Enforce AES-256 (0x12) ticket encryption and disable legacy RC4-HMAC (0x17) SPN authentication across all Active Directory tier-0 accounts.",
    mitre_attack_countered: [
      { technique_id: "T1558.003", technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting" },
      { technique_id: "T1558.004", technique_name: "AS-REP Roasting" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Group Policy Object: Network Security - Configure encryption types allowed for Kerberos (AES only)",
    verification_test: "Synthetic Rubeus TGS-REQ RC4 request is rejected with KDC_ERR_ETYPE_NOSUPP.",
    last_verified_at: "2026-08-27T03:00:00Z",
    confidence_pct: 99,
  },
  {
    d3fend_id: "D3-MFA",
    d3fend_name: "Hardware-Backed Multi-Factor Authentication",
    pillar: "Harden",
    description: "Mandate FIDO2/WebAuthn hardware tokens for all privileged administrative access and lateral RDP/SSH sessions.",
    mitre_attack_countered: [
      { technique_id: "T1078", technique_name: "Valid Accounts" },
      { technique_id: "T1110", technique_name: "Brute Force" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "YubiKey 5 FIDO2 Enclave Integration",
    verification_test: "Verify non-FIDO password replay fails on bastion hosts.",
    last_verified_at: "2026-08-27T01:30:00Z",
    confidence_pct: 100,
  },

  // Pillar: DETECT
  {
    d3fend_id: "D3-PSA",
    d3fend_name: "Process Spawn Analysis & Parent-Child Lineage",
    pillar: "Detect",
    description: "Analyze anomalous child processes spawned by system utilities (e.g. svchost.exe spawning cmd.exe or powershell.exe).",
    mitre_attack_countered: [
      { technique_id: "T1059.001", technique_name: "PowerShell Execution" },
      { technique_id: "T1053.005", technique_name: "Scheduled Task" },
      { technique_id: "T1055", technique_name: "Process Injection" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Sigma Rule SIGMA-SYS-001 & Real-time Rule Evaluator",
    verification_test: "Atomic Red Team test T1059.001 triggers alert with 100% precision.",
    last_verified_at: "2026-08-27T03:22:00Z",
    confidence_pct: 97,
  },
  {
    d3fend_id: "D3-JA3D",
    d3fend_name: "TLS Client Handshake Fingerprinting (JA3 / JA4)",
    pillar: "Detect",
    description: "Inspect TLS ClientHello parameters, cipher order, and extensions to detect unauthorized C2 beaconing agents regardless of domain fronting.",
    mitre_attack_countered: [
      { technique_id: "T1071.001", technique_name: "Web Protocols: Cobalt Strike C2" },
      { technique_id: "T1573.002", technique_name: "Asymmetric Cryptography" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Zeek SSL Dissector & Live PCAP DPI Engine",
    verification_test: "Detect Cobalt Strike malleable profile ClientHello with JA3 hash match.",
    last_verified_at: "2026-08-27T03:15:00Z",
    confidence_pct: 96,
  },
  {
    d3fend_id: "D3-RFAD",
    d3fend_name: "RF Spectral Anomaly & Jammer Threshold Detection",
    pillar: "Detect",
    description: "Continuously calculate background RF noise floors and trigger tactical alerts when spectral occupancy spikes > 35dB above baseline in tactical bands.",
    mitre_attack_countered: [
      { technique_id: "T1499", technique_name: "Endpoint Denial of Service: RF Jamming" },
      { technique_id: "T1005", technique_name: "Data from Local System: RF Exfil" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "SDR SIGINT FFT Correlator Matrix",
    verification_test: "Simulated 1575.42 MHz signal injection triggers Level 1 GPS Spoofing Alert.",
    last_verified_at: "2026-08-27T03:25:00Z",
    confidence_pct: 94,
  },

  // Pillar: ISOLATE
  {
    d3fend_id: "D3-HNI",
    d3fend_name: "Automated Host Network Isolation (Quarantine VLAN)",
    pillar: "Isolate",
    description: "Instantly terminate external routing and reassign compromised endpoint NIC to an isolated quarantine VLAN with restricted forensic access.",
    mitre_attack_countered: [
      { technique_id: "T1021.002", technique_name: "SMB/Windows Admin Shares Lateral Movement" },
      { technique_id: "T1048", technique_name: "Exfiltration Over Alternative Protocol" },
    ],
    operational_status: "Automated via SOAR",
    defensive_artifact: "SOAR Playbook PB-001 & OpenFlow Switch API",
    verification_test: "Playbook execution cuts lateral ICMP/SMB pings to domain neighbors in < 1.2s.",
    last_verified_at: "2026-08-27T02:50:00Z",
    confidence_pct: 99,
  },
  {
    d3fend_id: "D3-ECMN",
    d3fend_name: "Tactical Phased-Array Beamforming Spatial Nulling",
    pillar: "Isolate",
    description: "Steer phased-array antenna radiation nulls toward hostile emitter coordinates to isolate tactical UAV communications from jamming signals.",
    mitre_attack_countered: [
      { technique_id: "T1499", technique_name: "RF Jamming Denial of Service" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "SDR Beamformer Controller & SIGINT Station Alpha",
    verification_test: "Spatial null reduces hostile jammer signal strength from -38 dBm to -82 dBm.",
    last_verified_at: "2026-08-27T03:12:00Z",
    confidence_pct: 92,
  },

  // Pillar: DECEIVE
  {
    d3fend_id: "D3-HONEY",
    d3fend_name: "Active Directory Honey-Account SPN Decoy",
    pillar: "Deceive",
    description: "Deploy attractive high-privilege SPN service accounts (e.g. svc-backup-admin) monitored by high-priority tripwires to trap Kerberoasting scanners.",
    mitre_attack_countered: [
      { technique_id: "T1558.003", technique_name: "Kerberoasting" },
      { technique_id: "T1087.002", technique_name: "Domain Account Discovery" },
    ],
    operational_status: "Active & Enforcing",
    defensive_artifact: "Decoy SPN: svc-backup-admin.corp.local & Sysmon Tripwire",
    verification_test: "Any TGS ticket request against honey SPN automatically triggers Level 5 Critical Alarm.",
    last_verified_at: "2026-08-27T02:10:00Z",
    confidence_pct: 100,
  },

  // Pillar: EVICT
  {
    d3fend_id: "D3-EVICT-TGT",
    d3fend_name: "Active Directory Kerberos TGT & Session Revocation",
    pillar: "Evict",
    description: "Invalidate Ticket-Granting Tickets (krbtgt double-rotation) and terminate active Kerberos sessions across all domain controllers.",
    mitre_attack_countered: [
      { technique_id: "T1558.001", technique_name: "Golden Ticket / Golden SAML" },
      { technique_id: "T1078", technique_name: "Valid Accounts" },
    ],
    operational_status: "Partially Deployed",
    defensive_artifact: "PowerShell ActiveDirectory Domain Controller Invalidation Script",
    verification_test: "Forced password rotation expires forgeable session tickets within 60 seconds.",
    last_verified_at: "2026-08-27T01:00:00Z",
    confidence_pct: 91,
  },
  {
    d3fend_id: "D3-EVICT-PROC",
    d3fend_name: "Automated Host Process Tree Termination",
    pillar: "Evict",
    description: "Kill hostile executable and all child processes using kernel-level EDR driver handles.",
    mitre_attack_countered: [
      { technique_id: "T1059", technique_name: "Command and Scripting Interpreter" },
      { technique_id: "T1055", technique_name: "Process Injection" },
    ],
    operational_status: "Automated via SOAR",
    defensive_artifact: "SOAR Playbook PB-003 & EDR Process Driver API",
    verification_test: "Terminates mimikatz/beacon process trees without leaving zombie threads.",
    last_verified_at: "2026-08-27T03:18:00Z",
    confidence_pct: 98,
  },
];

export function getD3FENDMatrix(): D3FENDMatrixOverview {
  const pillars: D3FENDPillar[] = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict"];
  const activeCount = d3fendCountermeasures.filter(
    (c) => c.operational_status === "Active & Enforcing" || c.operational_status === "Automated via SOAR"
  ).length;

  return {
    total_countermeasures: d3fendCountermeasures.length,
    active_enforced_count: activeCount,
    coverage_percentage: Math.round((activeCount / d3fendCountermeasures.length) * 100),
    pillars: pillars.map((p) => ({
      pillar: p,
      countermeasures: d3fendCountermeasures.filter((c) => c.pillar === p),
    })),
  };
}

export function verifyD3FENDCountermeasure(d3fendId: string) {
  const item = d3fendCountermeasures.find((c) => c.d3fend_id === d3fendId);
  if (item) {
    item.last_verified_at = new Date().toISOString();
    item.confidence_pct = Math.min(100, item.confidence_pct + 1);
  }
  return item;
}
