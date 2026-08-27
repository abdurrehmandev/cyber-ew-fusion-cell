import { TacticalSitrepReport, SitrepDamageAssessment } from "../src/types";

export function generateSitrepReport(
  incidentId: string = "INC-2026-EW-089",
  classification: "UNCLASSIFIED" | "SECRET // NOFORN" | "TOP SECRET // SCI // TK" = "SECRET // NOFORN",
  reportingUnit: string = "Joint Tactical Cyber-EW Fusion Taskforce (CTF-71)"
): TacticalSitrepReport {
  const now = new Date();
  const day = String(now.getUTCDate()).padStart(2, "0");
  const hours = String(now.getUTCHours()).padStart(2, "0");
  const minutes = String(now.getUTCMinutes()).padStart(2, "0");
  const monthNames = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
  const dtg = `${day}${hours}${minutes}Z ${monthNames[now.getUTCMonth()]} ${now.getUTCFullYear()}`;

  const damageAssessment: SitrepDamageAssessment = {
    compromised_endpoints_count: 7,
    active_directory_domain_risk: "CRITICAL",
    scada_substation_status: "ISOLATED",
    grid_capacity_impact_mw: 420.5,
    financial_impact_est_usd: 1280000,
    rto_hours: 4.5,
    threat_containment_pct: 88.4,
    pcap_exfil_bytes: 48920140
  };

  return {
    report_id: `SITREP-${incidentId}-${Date.now().toString().slice(-6)}`,
    generated_at: now.toISOString(),
    dtg_military_timestamp: dtg,
    classification,
    operation_codename: "OPERATION SPECTRAL SENTINEL",
    reporting_unit: reportingUnit,
    incident_id: incidentId,
    threat_actor: "Sandworm (APT28) & Cozy Bear (APT29) Multi-Prong Incursion",
    executive_summary:
      "Joint Cyber-EW Taskforce has intercepted a synchronized offensive targeting Critical Energy Infrastructure (Substation 14) and Active Directory Domain Controllers. Coordinated adversary EW jamming on 433.92 MHz and GPS L1 desynchronization (+1.2s drift) was executed alongside Modbus/TCP breaker trip commands and Kerberos RC4 ticket extraction. Active D3FEND spatial nulling and host quarantine have contained 88.4% of lateral vectors.",
    damage_assessment: damageAssessment,
    active_mitre_techniques: ["T1595.002", "T1498.001", "T0855", "T1558.003", "T1071.001", "T1048.003"],
    active_d3fend_countermeasures: ["D3-ECMN", "D3-GPSA", "D3-PRC", "D3-KROT", "D3-FQDN", "D3-JA3D"],
    sections: [
      {
        paragraph_number: "1. SITUATION",
        title: "Operational Environment & Enemy Forces",
        subsections: [
          {
            subtitle: "Enemy Capabilities & Order of Battle",
            content:
              "State-sponsored cyber-physical threat actors operating mobile software-defined radio (SDR) platforms and advanced living-off-the-land malware implants. Primary TTPs include RF spectral recon on 433 MHz, GPS ephemeris spoofing, SCADA Modbus coil force manipulation, and Active Directory Kerberoasting.",
            key_bullet_points: [
              "Hostile SDR Emitter 0x9F4E detected at Bearings 042° / 088° relative to Mast Alpha.",
              "Malicious C2 IP 198.51.100.89 confirmed active with JA3 hash 51c64c77e60f39ac3e97c803f8e4980e.",
              "GPS L1 Time-drift injection induced 1.24 second phase skew across Substation 14 PMUs."
            ]
          },
          {
            subtitle: "Friendly Cyber & EW Defense Disposition",
            content:
              "CTF-71 sensor grid active with 4 fixed SIGINT masts, mobile SDR intercept vehicles, and inline deep packet inspection (DPI) taps operating across 10G backbone trunks."
          }
        ]
      },
      {
        paragraph_number: "2. MISSION",
        title: "Defensive Tactical Objectives",
        subsections: [
          {
            subtitle: "Primary Mission Directive",
            content:
              "Neutralize hostile RF jamming vectors, enforce Zero-Trust micro-isolation across Substation 14 OT enclaves, rotate compromised Active Directory Kerberos Golden/Silver Ticket keys (KRBTGT), and preserve regional power grid stability without blackout."
          }
        ]
      },
      {
        paragraph_number: "3. EXECUTION",
        title: "Defensive Countermeasures & Tactical Scheme of Maneuver",
        subsections: [
          {
            subtitle: "Active Electronic Countermeasures (ECM / D3FEND)",
            content:
              "Deployed adaptive phased-array spatial nulling on 433.92 MHz to carve a 32 dB attenuation notch towards hostile emitter azimuth. Initiated GNSS anti-spoofing sanity filters comparing L1/L2 phase deltas with local atomic rubidium reference clocks.",
            key_bullet_points: [
              "D3-ECMN: Electronic Countermeasure Nulling verified at 94.2% suppression efficiency.",
              "D3-GPSA: Multi-constellation GNSS fallback engaged across all PMU sensors."
            ]
          },
          {
            subtitle: "Cyber Enclave Containment & Host Isolation",
            content:
              "Automated CACAO 2.0 SOAR playbook severed SCADA Modbus TCP port 502 routing to DMZ. Enforced dynamic VLAN quarantine on 7 compromised endpoints (WS-FIN-09, DC-ROOT-01, RTU-GATEWAY-14)."
          }
        ]
      },
      {
        paragraph_number: "4. ADMINISTRATION & LOGISTICS",
        title: "Forensic Evidence & Collateral Impact",
        subsections: [
          {
            subtitle: "Chain of Custody & STIX 2.1 Manifest",
            content:
              "All raw PCAP forensic captures (14.2 MB), STIX 2.1 threat graphs, and CACAO 2.0 JSON playbooks sealed under Merkle Tree Root SHA-256 (3b9f4e...e21a) with ED25519 digital witness verification.",
            key_bullet_points: [
              "Package ID: PKG-AIRGAP-2026-EW089-9142",
              "Forensic Custodian: Senior Cyber-EW Watch Officer",
              "Integrity Status: Authenticated Cryptographically Sealed"
            ]
          },
          {
            subtitle: "System Outages & Power Impact",
            content:
              "420.5 MW load safely rerouted through auxiliary transmission feeders 1 & 2. Zero civilian blackout sustained; grid telemetry latency stabilized to < 18ms."
          }
        ]
      },
      {
        paragraph_number: "5. COMMAND & SIGNAL",
        title: "Command Authority & Communications Security (COMSEC)",
        subsections: [
          {
            subtitle: "Watch Officer Command Roster",
            content:
              "Joint Operations Center (JOC) Watch Officer in primary tactical control. Deputy Incident Commander delegated automated SOAR playbook execution approval."
          },
          {
            subtitle: "Fallback Communications & Frequency Allocations",
            content:
              "Primary Defense Voice: Secure Tactical VHF Channel Bravo (142.850 MHz NFM CTCSS 114.8 Hz). Emergency Fallback: Encrypted SATCOM BGAN Terminal 4.",
            key_bullet_points: [
              "COMSEC Status: DEFCON 2 / EMCON Condition Charlie.",
              "Emergency Frequency: 142.850 MHz (CTCSS 114.8 Hz)."
            ]
          }
        ]
      }
    ]
  };
}
