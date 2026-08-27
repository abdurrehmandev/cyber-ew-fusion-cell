import { AdversaryScenario, SimulationState, SimulationStep } from "../src/types";

export const SCENARIOS: AdversaryScenario[] = [
  {
    id: "scen-sandworm-scada",
    title: "APT28 / Sandworm - SCADA Substation Blackout & GPS Spoof",
    threat_actor: "Sandworm (APT28 / Unit 74455)",
    target_sector: "Energy Grid & Critical Infrastructure",
    severity: "Critical",
    category: "SCADA / Grid Blackout",
    summary: "Multi-domain coordinated attack combining RF GPS L1 desynchronization with unauthorized IEC 60870-5-104 / Modbus SCADA command injection targeting Substation 14.",
    complexity: "Advanced Multi-Stage",
    estimated_duration_sec: 180,
    iocs_involved: {
      ips: ["192.168.10.14", "198.51.100.89", "10.200.4.15"],
      domains: ["time-sync-ntp.mil-proxy.ru", "grid-update.scada-telemetry.org"],
      hashes: ["a847f9c2d76e829104bcde1190471ea84b5c77e6820c8b", "4b3f81e82a9910d32f50091398cfae4981"],
      rf_frequencies: ["1575.42 MHz (GPS L1)", "433.92 MHz (Telemetry)"]
    },
    steps: [
      {
        step_number: 1,
        name: "RF Reconnaissance & Perimeter Spectrum Scan",
        domain: "RF / Electronic Warfare",
        mitre_technique: "T1595.002",
        technique_name: "Vulnerability Scanning / RF Spectral Recon",
        description: "Hostile SDR vehicle sweeps 433 MHz and 1.5 GHz bands, analyzing perimeter sensor mast emissions.",
        artifact_payload: "RF_BURST_FREQ=433.92MHz POWER=-42dBm MODULATION=GFSK",
        expected_alert: "Tactical EW: Unauthorized Wideband RF Sweep Detected near Mast Alpha",
        d3fend_countermeasure_id: "D3-ECMN",
        status: "Pending"
      },
      {
        step_number: 2,
        name: "GPS L1 Time-Sync Spoofing & Desynchronization",
        domain: "Physical / GIS",
        mitre_technique: "T1498.001",
        technique_name: "Network / Physical Denial of Service (GNSS Spoofing)",
        description: "Adversary emits false ephemeris signals (+1.2s drift) to disrupt Phasor Measurement Unit (PMU) timestamps.",
        artifact_payload: "GNSS_SPOOF_PRN=14 LAT_DRIFT=+0.0042 LON_DRIFT=-0.0031 TIME_SKEW=+1240ms",
        expected_alert: "SIGINT Geo: GPS L1 Desync & Spoofing Bubble Active over Substation Grid",
        d3fend_countermeasure_id: "D3-GPSA",
        status: "Pending"
      },
      {
        step_number: 3,
        name: "Modbus / IEC-104 SCADA Command Injection",
        domain: "Network / DPI",
        mitre_technique: "T0855",
        technique_name: "Unauthorized Command Message (ICS / SCADA)",
        description: "Injected TCP stream writes malicious coil values (Function 0x05) to trip feeder breakers 3 & 4.",
        artifact_payload: "MODBUS_TCP: UnitID=0x01 Func=0x05 (Force Single Coil) Addr=0x0014 Data=0xFF00",
        expected_alert: "DPI Alarm: Anomalous Modbus RTU/TCP Trip Sequence without HMI Authorization",
        d3fend_countermeasure_id: "D3-PRC",
        status: "Pending"
      },
      {
        step_number: 4,
        name: "BlackEnergy 3 Wiper Payload Deployment",
        domain: "Cyber",
        mitre_technique: "T1561.002",
        technique_name: "Disk Structure Wipe",
        description: "Adversary launches scheduled task executing rundll32.exe with encrypted wiper DLL into RTU gateway.",
        artifact_payload: "schtasks.exe /create /tn SCADA_Watchdog /tr \"rundll32.exe C:\\Windows\\Temp\\srvmgr.dll,Run\" /sc onstart",
        expected_alert: "EDR Sigma Rule: Suspicious Scheduled Task Spawning DLL in Temp Directory",
        d3fend_countermeasure_id: "D3-FSI",
        status: "Pending"
      },
      {
        step_number: 5,
        name: "Substation 14 Total Feeder Trip & C2 Beaconing",
        domain: "Cyber",
        mitre_technique: "T1071.001",
        technique_name: "Web Protocols (Encrypted C2 Exfil)",
        description: "Beacon transmits telemetry confirmation to external command IP over HTTPS with JA3 51c64c77e60f39ac3e97c803f8e4980e.",
        artifact_payload: "POST /api/v2/telemetry/confirm HTTP/1.1 Host: 198.51.100.89 JA3=51c64c77e60f39ac3e97c803f8e4980e",
        expected_alert: "SOC Alert: Outbound C2 Beaconing Matched Threat Actor Infrastructure",
        d3fend_countermeasure_id: "D3-JA3D",
        status: "Pending"
      }
    ]
  },
  {
    id: "scen-cozybear-kerberoast",
    title: "APT29 / Cozy Bear - Active Directory Kerberoasting & Stealth C2",
    threat_actor: "Cozy Bear (APT29 / Nobelium)",
    target_sector: "Government & Defense Industrial Base",
    severity: "High",
    category: "Stealth C2 & Active Directory",
    summary: "Stealthy lateral movement campaign utilizing low-reputation RC4-HMAC Kerberos service ticket requests, memory injection, and DNS covert tunneling.",
    complexity: "Low & Slow Tactical",
    estimated_duration_sec: 150,
    iocs_involved: {
      ips: ["192.168.1.55", "10.0.0.1", "203.0.113.195"],
      domains: ["update.corp-support-sync.com", "ns1.tunnel-dns-c2.net"],
      hashes: ["c27a98dfb01e3892ca82e449910d512a839e120f", "e10adc3949ba59abbe56e057f20f883e"],
      rf_frequencies: ["2.412 GHz (Wi-Fi Ch 1)"]
    },
    steps: [
      {
        step_number: 1,
        name: "Spearphishing Initial Access via Malicious Word Macro",
        domain: "Cyber",
        mitre_technique: "T1566.001",
        technique_name: "Spearphishing Attachment",
        description: "Target user opens DEFENSE_BUDGET_2026.docm containing VBA macro that drops loader payload.",
        artifact_payload: "WINWORD.EXE -> cmd.exe /c powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAA...",
        expected_alert: "EDR Sigma Rule: Office Application Spawning Encoded PowerShell Process",
        d3fend_countermeasure_id: "D3-EDR",
        status: "Pending"
      },
      {
        step_number: 2,
        name: "Kerberoasting - SPN Ticket Request with RC4 Downgrade",
        domain: "Network / DPI",
        mitre_technique: "T1558.003",
        technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting",
        description: "Adversary requests TGS-REQ for MSSQLSvc/db01.corp with cipher 0x17 (RC4-HMAC) to crack offline.",
        artifact_payload: "KERBEROS_TGS_REQ: Service=MSSQLSvc/db01.corp.internal Enctype=0x17 (rc4-hmac) TicketLen=1420",
        expected_alert: "PCAP Dissector Alert: Anomalous Kerberos RC4-HMAC Ticket Extraction (Kerberoasting)",
        d3fend_countermeasure_id: "D3-CH",
        status: "Pending"
      },
      {
        step_number: 3,
        name: "Process Injection into LSASS Memory",
        domain: "Cyber",
        mitre_technique: "T1055.001",
        technique_name: "Dynamic-link Library Injection",
        description: "Adversary injects reflective DLL into lsass.exe to dump plaintext NTLM hashes.",
        artifact_payload: "OpenProcess(PROCESS_VM_WRITE, PID=640 [lsass.exe]) -> VirtualAllocEx -> WriteProcessMemory",
        expected_alert: "EDR Alert: Cross-Process VirtualAllocEx Memory Access to LSASS by Unsigned Binary",
        d3fend_countermeasure_id: "D3-MFA",
        status: "Pending"
      },
      {
        step_number: 4,
        name: "DNS Covert Tunneling & Data Exfiltration",
        domain: "Network / DPI",
        mitre_technique: "T1071.004",
        technique_name: "Application Layer Protocol: DNS",
        description: "Base32-encoded stolen hashes exfiltrated via high-entropy DNS TXT and A record queries.",
        artifact_payload: "DNS_QUERY: a94f71a09bc12e4.exfil.tunnel-dns-c2.net (Entropy=4.82 bits/symbol)",
        expected_alert: "DPI Entropy Alert: DNS Tunneling Anomaly Detected (High Shannon Entropy > 4.5)",
        d3fend_countermeasure_id: "D3-DNF",
        status: "Pending"
      }
    ]
  },
  {
    id: "scen-tactical-uav-jam",
    title: "Hostile Tactical UAV Swarm & Electronic Warfare Assault",
    threat_actor: "Red Force Tactical Drone Unit (Unit 891-EW)",
    target_sector: "Tactical Forward Operating Base / Perimeter",
    severity: "Critical",
    category: "Tactical Drone EW Incursion",
    summary: "Coordinated drone swarm assault employing Frequency Hopping Spread Spectrum (FHSS) telemetry and multi-band noise jamming against tactical Wi-Fi mesh.",
    complexity: "High-Velocity Burst",
    estimated_duration_sec: 120,
    iocs_involved: {
      ips: ["172.16.88.10", "172.16.88.254"],
      domains: ["drone-c2.tactical-proxy.net"],
      hashes: ["f2d8471e984bc01928471e847192837491028374"],
      rf_frequencies: ["433.50 MHz", "868.10 MHz", "2.450 GHz", "5.820 GHz"]
    },
    steps: [
      {
        step_number: 1,
        name: "UAV Swarm Ingress & FHSS Control Link Activation",
        domain: "RF / Electronic Warfare",
        mitre_technique: "T1005",
        technique_name: "Data from Local System / Covert RF C2 Channel",
        description: "3 rotary-wing micro-UAVs cross northern perimeter, emitting 200 hops/sec on 433-435 MHz band.",
        artifact_payload: "RF_EMISSION_HOPPING: CenterFreq=434.0MHz Bandwidth=2MHz HopRate=220hops/sec",
        expected_alert: "Tactical EW: Fast-Hopping FHSS Emitter Detected by Mast Alpha & Roof Bravo",
        d3fend_countermeasure_id: "D3-ECMN",
        status: "Pending"
      },
      {
        step_number: 2,
        name: "Directional AoA Triangulation & Multi-Station Bearings",
        domain: "Physical / GIS",
        mitre_technique: "T1046",
        technique_name: "Network Service Discovery / RF Emitter Geolocation",
        description: "Sensor stations Alpha (042°), Bravo (318°), and Rover Echo (085°) calculate target CEP fix.",
        artifact_payload: "SIGINT_AOA: Alpha=042.5deg Bravo=318.2deg Rover=085.0deg Fix=(37.7792, -122.4140) CEP=18m",
        expected_alert: "Tactical GIS: Hostile UAV Emitter Localized at MGRS 10SEG 0482 8912",
        d3fend_countermeasure_id: "D3-SDO",
        status: "Pending"
      },
      {
        step_number: 3,
        name: "Tactical Wi-Fi Mesh Jamming & Denial-of-Service",
        domain: "RF / Electronic Warfare",
        mitre_technique: "T1498.001",
        technique_name: "RF Jamming Denial of Service",
        description: "High-power barrage jamming injected across 2.412 - 2.462 GHz (J/S ratio = +18 dB).",
        artifact_payload: "JAMMING_BURST: Band=2.4GHz Type=BarrageNoise J_S_Ratio=+18.4dB PacketLoss=82%",
        expected_alert: "Spectrum Alert: Tactical Wi-Fi Mesh Severe Jamming Degradation Bubble Active",
        d3fend_countermeasure_id: "D3-PSN",
        status: "Pending"
      },
      {
        step_number: 4,
        name: "Automated Phased-Array Spatial Nulling & Frequency Agility",
        domain: "RF / Electronic Warfare",
        mitre_technique: "T1071",
        technique_name: "Defensive Counter-EW Execution",
        description: "SOC executes D3-PSN steerable null towards azimuth 042°, restoring friendly telemetry.",
        artifact_payload: "D3FEND_ACTION: Steerable Null -35dB at Azimuth 042.5deg Frequency Hopped to 5.84 GHz",
        expected_alert: "D3FEND Matrix: Phased-Array Spatial Nulling Restored Mesh Signal Margin to +12 dB",
        d3fend_countermeasure_id: "D3-PSN",
        status: "Pending"
      }
    ]
  }
];

let currentSimulationState: SimulationState = {
  active_scenario_id: null,
  status: "Idle",
  current_step_index: 0,
  total_steps: 0,
  elapsed_sec: 0,
  events_generated: 0,
  alerts_fired: 0,
  d3fend_blocks_triggered: 0,
  logs: [
    {
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: "Simulation engine initialized. Ready for threat scenario injection.",
      step_number: 0
    }
  ]
};

export function getSimulationScenarios(): AdversaryScenario[] {
  return SCENARIOS;
}

export function getSimulationState(): SimulationState {
  return currentSimulationState;
}

export function startSimulation(scenarioId: string): { status: string; state: SimulationState } {
  const scenario = SCENARIOS.find(s => s.id === scenarioId);
  if (!scenario) {
    throw new Error(`Scenario ${scenarioId} not found`);
  }

  // Reset steps
  scenario.steps.forEach(step => {
    step.status = "Pending";
    step.injected_at = undefined;
  });

  currentSimulationState = {
    active_scenario_id: scenarioId,
    status: "Running",
    current_step_index: 0,
    total_steps: scenario.steps.length,
    elapsed_sec: 0,
    events_generated: 0,
    alerts_fired: 0,
    d3fend_blocks_triggered: 0,
    logs: [
      {
        timestamp: new Date().toISOString(),
        level: "INFO",
        message: `Launched simulation: [${scenario.threat_actor}] - ${scenario.title}`,
        step_number: 0
      }
    ]
  };

  return { status: "started", state: currentSimulationState };
}

export function injectNextStep(): { step: SimulationStep | null; state: SimulationState } {
  if (!currentSimulationState.active_scenario_id) {
    throw new Error("No active simulation running");
  }

  const scenario = SCENARIOS.find(s => s.id === currentSimulationState.active_scenario_id);
  if (!scenario) {
    throw new Error("Active scenario not found");
  }

  const stepIndex = currentSimulationState.current_step_index;
  if (stepIndex >= scenario.steps.length) {
    currentSimulationState.status = "Completed";
    currentSimulationState.logs.push({
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: `Scenario ${scenario.title} fully completed. All attack vectors injected and triaged.`,
      step_number: stepIndex
    });
    return { step: null, state: currentSimulationState };
  }

  const step = scenario.steps[stepIndex];
  step.status = "Injected";
  step.injected_at = new Date().toISOString();

  currentSimulationState.current_step_index += 1;
  currentSimulationState.elapsed_sec += 15;
  currentSimulationState.events_generated += Math.floor(Math.random() * 8) + 4;
  currentSimulationState.alerts_fired += 1;
  if (step.d3fend_countermeasure_id) {
    currentSimulationState.d3fend_blocks_triggered += 1;
  }

  currentSimulationState.logs.push({
    timestamp: new Date().toISOString(),
    level: "ALERT",
    message: `[Step ${step.step_number}] Injected ${step.name} (${step.mitre_technique}). Alert: ${step.expected_alert}`,
    step_number: step.step_number
  });

  if (step.d3fend_countermeasure_id) {
    currentSimulationState.logs.push({
      timestamp: new Date().toISOString(),
      level: "DEFENSE",
      message: `[D3FEND Countermeasure] Triggered ${step.d3fend_countermeasure_id} defense rule against technique ${step.mitre_technique}`,
      step_number: step.step_number
    });
  }

  if (currentSimulationState.current_step_index >= scenario.steps.length) {
    currentSimulationState.status = "Completed";
  }

  return { step, state: currentSimulationState };
}

export function burstExecuteSimulation(): { state: SimulationState; steps: SimulationStep[] } {
  if (!currentSimulationState.active_scenario_id) {
    throw new Error("No active scenario running");
  }

  const scenario = SCENARIOS.find(s => s.id === currentSimulationState.active_scenario_id);
  if (!scenario) {
    throw new Error("Scenario not found");
  }

  scenario.steps.forEach(step => {
    step.status = "Injected";
    step.injected_at = new Date().toISOString();
    currentSimulationState.events_generated += 6;
    currentSimulationState.alerts_fired += 1;
    if (step.d3fend_countermeasure_id) {
      currentSimulationState.d3fend_blocks_triggered += 1;
    }
  });

  currentSimulationState.current_step_index = scenario.steps.length;
  currentSimulationState.status = "Completed";
  currentSimulationState.elapsed_sec = scenario.estimated_duration_sec;
  currentSimulationState.logs.push({
    timestamp: new Date().toISOString(),
    level: "WARN",
    message: `Burst execution completed: Injected all ${scenario.steps.length} stages into live telemetry stream.`,
    step_number: scenario.steps.length
  });

  return { state: currentSimulationState, steps: scenario.steps };
}

export function resetSimulation(): SimulationState {
  SCENARIOS.forEach(s => {
    s.steps.forEach(st => {
      st.status = "Pending";
      st.injected_at = undefined;
    });
  });

  currentSimulationState = {
    active_scenario_id: null,
    status: "Idle",
    current_step_index: 0,
    total_steps: 0,
    elapsed_sec: 0,
    events_generated: 0,
    alerts_fired: 0,
    d3fend_blocks_triggered: 0,
    logs: [
      {
        timestamp: new Date().toISOString(),
        level: "INFO",
        message: "Simulation sandbox reset to baseline nominal state.",
        step_number: 0
      }
    ]
  };

  return currentSimulationState;
}

export function addCustomScenario(draft: Partial<AdversaryScenario>): AdversaryScenario {

  const newScenario: AdversaryScenario = {
    id: draft.id || `custom-scen-${Date.now()}`,
    title: draft.title || "Custom Multi-Domain Threat Campaign",
    threat_actor: draft.threat_actor || "Custom Threat Actor",
    target_sector: draft.target_sector || "Critical Infrastructure",
    severity: draft.severity || "High",
    category: (draft.category as any) || "SCADA / Grid Blackout",
    summary: draft.summary || "Custom tailored multi-domain adversary campaign generated in Studio.",
    complexity: draft.complexity || "Advanced Multi-Stage",
    estimated_duration_sec: draft.estimated_duration_sec || 120,
    iocs_involved: draft.iocs_involved || {
      ips: ["192.168.1.99"],
      domains: ["custom-c2.infra.mil"],
      hashes: ["e10adc3949ba59abbe56e057f20f883e"],
      rf_frequencies: ["433.92 MHz"]
    },
    steps: draft.steps && draft.steps.length > 0 ? draft.steps : [
      {
        step_number: 1,
        name: "Initial Ingress & RF Beaconing",
        domain: "Cyber",
        mitre_technique: "T1566.001",
        technique_name: "Spearphishing Attachment",
        description: "Adversary implants weaponized macro document executing reverse shell.",
        artifact_payload: "powershell.exe -enc SQBFAFgA...",
        expected_alert: "EDR Alarm: Suspicious Encoded PowerShell Spawned",
        d3fend_countermeasure_id: "D3-PSA",
        status: "Pending"
      }
    ]
  };

  SCENARIOS.push(newScenario);
  return newScenario;
}

export function deleteCustomScenario(id: string): boolean {
  const index = SCENARIOS.findIndex(s => s.id === id);
  if (index !== -1) {
    SCENARIOS.splice(index, 1);
    return true;
  }
  return false;
}

