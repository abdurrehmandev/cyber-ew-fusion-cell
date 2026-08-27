import { BlastRadiusNode, BlastRadiusEdge, BlastRadiusState } from "../src/types";

const INITIAL_NODES: BlastRadiusNode[] = [
  {
    id: "WS-FIN-09",
    label: "WS-FIN-09 (Finance Workstation)",
    type: "workstation",
    zone: "Corporate IT",
    criticality: "Medium",
    status: "Clean",
    ip: "192.168.1.55",
    operating_system: "Windows 11 Enterprise (23H2)",
    vulnerability: "CVE-2024-38077 (Remote RPC / Phish Vector)",
    financial_value_usd: 45000,
    power_draw_mw: 0.05
  },
  {
    id: "WS-ENG-02",
    label: "WS-ENG-02 (SCADA Engineering Laptop)",
    type: "workstation",
    zone: "Corporate IT",
    criticality: "High",
    status: "Clean",
    ip: "192.168.1.82",
    operating_system: "Windows 10 Enterprise LTSC",
    vulnerability: "Cached Dual-Homed VPN Credentials",
    financial_value_usd: 120000,
    power_draw_mw: 0.05
  },
  {
    id: "DC-ROOT-01",
    label: "DC-ROOT-01 (Primary Domain Controller)",
    type: "domain_controller",
    zone: "Active Directory",
    criticality: "Crown Jewel",
    status: "Clean",
    ip: "10.0.0.1",
    operating_system: "Windows Server 2022",
    vulnerability: "Kerberoastable SPN / KRBTGT Key Exposure",
    financial_value_usd: 850000,
    power_draw_mw: 0.1
  },
  {
    id: "DC-BACKUP-02",
    label: "DC-BACKUP-02 (Backup Domain Controller)",
    type: "domain_controller",
    zone: "Active Directory",
    criticality: "High",
    status: "Clean",
    ip: "10.0.0.2",
    operating_system: "Windows Server 2022",
    vulnerability: "AD Replication Sync Trust",
    financial_value_usd: 350000,
    power_draw_mw: 0.1
  },
  {
    id: "SCADA-HMI-01",
    label: "SCADA-HMI-01 (Grid Dispatch Operator Console)",
    type: "scada_plc",
    zone: "OT / SCADA Enclave",
    criticality: "Crown Jewel",
    status: "Clean",
    ip: "10.200.4.15",
    operating_system: "Embedded Linux / WinCC Open",
    vulnerability: "Hardcoded ICS Operator Tokens",
    financial_value_usd: 950000,
    power_draw_mw: 120.0
  },
  {
    id: "RTU-GATEWAY-14",
    label: "RTU-GATEWAY-14 (Substation 14 Gateway)",
    type: "scada_plc",
    zone: "OT / SCADA Enclave",
    criticality: "Crown Jewel",
    status: "Clean",
    ip: "192.168.10.14",
    operating_system: "VxWorks RTOS",
    vulnerability: "Unauthenticated Modbus/TCP Port 502",
    financial_value_usd: 1400000,
    power_draw_mw: 240.0
  },
  {
    id: "PLC-BREAKER-03",
    label: "PLC-BREAKER-03 (High-Voltage Feeder Breaker)",
    type: "scada_plc",
    zone: "OT / SCADA Enclave",
    criticality: "High",
    status: "Clean",
    ip: "192.168.10.33",
    operating_system: "Siemens S7-1500 PLC",
    vulnerability: "Remote Force Single Coil (0x05)",
    financial_value_usd: 600000,
    power_draw_mw: 60.5
  },
  {
    id: "AWS-IAM-ADMIN",
    label: "AWS-IAM-ADMIN (Cloud Infrastructure Role)",
    type: "cloud_iam",
    zone: "AWS / Cloud",
    criticality: "Crown Jewel",
    status: "Clean",
    ip: "172.31.0.4",
    operating_system: "AWS IAM / STS",
    vulnerability: "sts:AssumeRole over-permissive trust",
    financial_value_usd: 1100000,
    power_draw_mw: 0.0
  },
  {
    id: "S3-CONFIDENTIAL-DATA",
    label: "S3-CONFIDENTIAL (Grid Topology & Blueprint Vault)",
    type: "database",
    zone: "AWS / Cloud",
    criticality: "High",
    status: "Clean",
    ip: "172.31.12.89",
    operating_system: "Amazon S3 Object Store",
    vulnerability: "Exfiltration via DNS / HTTPS tunnel",
    financial_value_usd: 750000,
    power_draw_mw: 0.0
  },
  {
    id: "SIGINT-MAST-ALPHA",
    label: "SIGINT-MAST-ALPHA (Tactical Spectrum Sensor)",
    type: "rf_sensor",
    zone: "Tactical EW",
    criticality: "Medium",
    status: "Clean",
    ip: "10.150.1.10",
    operating_system: "Ettus USRP SDR Embedded Linux",
    vulnerability: "RF In-Band Jamming Saturation",
    financial_value_usd: 180000,
    power_draw_mw: 0.2
  },
  {
    id: "C2-HOSTILE-NODE",
    label: "C2-HOSTILE-NODE (External Command Infrastructure)",
    type: "c2_beacon",
    zone: "Tactical EW",
    criticality: "Low",
    status: "Infected",
    ip: "198.51.100.89",
    operating_system: "Debian Linux C2 Server",
    vulnerability: "Threat Actor Weaponized Infrastructure",
    financial_value_usd: 0,
    power_draw_mw: 0.0
  }
];

const INITIAL_EDGES: BlastRadiusEdge[] = [
  { id: "e1", source: "WS-FIN-09", target: "DC-ROOT-01", protocol: "Kerberos RC4", is_compromised_path: false },
  { id: "e2", source: "WS-FIN-09", target: "WS-ENG-02", protocol: "SMB / RPC", is_compromised_path: false },
  { id: "e3", source: "DC-ROOT-01", target: "DC-BACKUP-02", protocol: "SMB / RPC", is_compromised_path: false },
  { id: "e4", source: "DC-ROOT-01", target: "AWS-IAM-ADMIN", protocol: "AWS IAM AssumeRole", is_compromised_path: false },
  { id: "e5", source: "WS-ENG-02", target: "SCADA-HMI-01", protocol: "SMB / RPC", is_compromised_path: false },
  { id: "e6", source: "SCADA-HMI-01", target: "RTU-GATEWAY-14", protocol: "Modbus / IEC-104", is_compromised_path: false },
  { id: "e7", source: "RTU-GATEWAY-14", target: "PLC-BREAKER-03", protocol: "Modbus / IEC-104", is_compromised_path: false },
  { id: "e8", source: "AWS-IAM-ADMIN", target: "S3-CONFIDENTIAL-DATA", protocol: "AWS IAM AssumeRole", is_compromised_path: false },
  { id: "e9", source: "SIGINT-MAST-ALPHA", target: "RTU-GATEWAY-14", protocol: "RF Burst 433MHz", is_compromised_path: false },
  { id: "e10", source: "C2-HOSTILE-NODE", target: "WS-FIN-09", protocol: "HTTPS C2", is_compromised_path: false }
];

let blastState: BlastRadiusState = {
  nodes: JSON.parse(JSON.stringify(INITIAL_NODES)),
  edges: JSON.parse(JSON.stringify(INITIAL_EDGES)),
  patient_zero_id: "WS-FIN-09",
  simulation_step: 0,
  is_propagating: false,
  total_loss_usd: 0,
  total_mw_lost: 0,
  compromised_nodes_count: 0,
  quarantined_nodes_count: 0,
  propagation_log: []
};

export function getBlastRadiusState(): BlastRadiusState {
  return blastState;
}

export function initializeBlastPatientZero(patientZeroId: string): BlastRadiusState {
  blastState.nodes = JSON.parse(JSON.stringify(INITIAL_NODES));
  blastState.edges = JSON.parse(JSON.stringify(INITIAL_EDGES));
  blastState.patient_zero_id = patientZeroId;
  blastState.simulation_step = 0;
  blastState.is_propagating = true;
  blastState.total_loss_usd = 0;
  blastState.total_mw_lost = 0;
  blastState.quarantined_nodes_count = 0;
  blastState.propagation_log = [];

  const pZero = blastState.nodes.find(n => n.id === patientZeroId);
  if (pZero) {
    pZero.status = "Patient Zero";
    pZero.infection_step = 0;
    pZero.infection_vector = "Initial Compromise (Patient Zero Ingress)";
    blastState.total_loss_usd = pZero.financial_value_usd;
    blastState.total_mw_lost = pZero.power_draw_mw || 0;
    blastState.compromised_nodes_count = 1;
    blastState.propagation_log.push({
      step: 0,
      timestamp: new Date().toISOString(),
      from_node: "External Ingress",
      to_node: pZero.id,
      protocol: "Phishing / Direct Ingress",
      vector: `Initial weaponization established on ${pZero.label}`
    });
  }

  return blastState;
}

export function stepBlastPropagation(): BlastRadiusState {
  if (!blastState.is_propagating) return blastState;

  const currentStep = blastState.simulation_step + 1;
  const infectedIds = new Set(
    blastState.nodes
      .filter(n => n.status === "Infected" || n.status === "Patient Zero")
      .map(n => n.id)
  );

  let newlyInfectedCount = 0;

  blastState.edges.forEach(edge => {
    const srcId = typeof edge.source === "string" ? edge.source : edge.source.id;
    const tgtId = typeof edge.target === "string" ? edge.target : edge.target.id;

    if (edge.blocked_by_d3fend) return;

    if (infectedIds.has(srcId) && !infectedIds.has(tgtId)) {
      const tgtNode = blastState.nodes.find(n => n.id === tgtId);
      if (tgtNode && tgtNode.status === "Clean") {
        tgtNode.status = "Infected";
        tgtNode.infection_step = currentStep;
        tgtNode.infection_vector = `Lateral spread via ${edge.protocol}`;
        edge.is_compromised_path = true;

        blastState.total_loss_usd += tgtNode.financial_value_usd;
        blastState.total_mw_lost += tgtNode.power_draw_mw || 0;
        newlyInfectedCount++;

        blastState.propagation_log.push({
          step: currentStep,
          timestamp: new Date().toISOString(),
          from_node: srcId,
          to_node: tgtId,
          protocol: edge.protocol,
          vector: `Contagion breached ${tgtNode.label} via ${edge.protocol}`
        });
      }
    }
  });

  blastState.simulation_step = currentStep;
  blastState.compromised_nodes_count = blastState.nodes.filter(
    n => n.status === "Infected" || n.status === "Patient Zero"
  ).length;

  if (newlyInfectedCount === 0 || blastState.simulation_step >= 5) {
    blastState.is_propagating = false;
  }

  return blastState;
}

export function quarantineNode(nodeId: string): BlastRadiusState {
  const node = blastState.nodes.find(n => n.id === nodeId);
  if (node) {
    node.status = "Quarantined";
    blastState.quarantined_nodes_count++;

    // Sever connected edges
    blastState.edges.forEach(edge => {
      const srcId = typeof edge.source === "string" ? edge.source : edge.source.id;
      const tgtId = typeof edge.target === "string" ? edge.target : edge.target.id;
      if (srcId === nodeId || tgtId === nodeId) {
        edge.blocked_by_d3fend = true;
        edge.is_compromised_path = false;
      }
    });

    blastState.propagation_log.push({
      step: blastState.simulation_step,
      timestamp: new Date().toISOString(),
      from_node: "D3FEND-SOAR",
      to_node: nodeId,
      protocol: "Micro-Segmentation",
      vector: `Enforced Zero-Trust isolation quarantine on ${node.label}`
    });
  }

  return blastState;
}

export function resetBlastSimulation(): BlastRadiusState {
  blastState = {
    nodes: JSON.parse(JSON.stringify(INITIAL_NODES)),
    edges: JSON.parse(JSON.stringify(INITIAL_EDGES)),
    patient_zero_id: "WS-FIN-09",
    simulation_step: 0,
    is_propagating: false,
    total_loss_usd: 0,
    total_mw_lost: 0,
    compromised_nodes_count: 0,
    quarantined_nodes_count: 0,
    propagation_log: []
  };
  return blastState;
}
