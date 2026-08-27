import React, { useState } from "react";
import {
  Palette,
  Plus,
  Trash2,
  Save,
  Play,
  Download,
  Upload,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Server,
  Shield,
  Layers,
  Sparkles,
  Zap
} from "lucide-react";
import { AdversaryScenario, SimulationStep } from "../../types";

interface Props {
  onScenarioCreated?: (scenario: AdversaryScenario) => void;
  onNavigateToSandbox?: () => void;
}

const TEMPLATES = [
  {
    name: "Offshore Wind Turbine OT Hijack & C-Band Jam",
    threat_actor: "Volt Typhoon (Vanguard)",
    sector: "Renewable Energy & Maritime Grid",
    category: "SCADA / Grid Blackout" as const,
    severity: "Critical" as const,
    complexity: "Advanced Multi-Stage" as const,
    duration: 180,
    steps: [
      {
        step_number: 1,
        name: "Maritime AIS & C-Band Telemetry Jamming",
        domain: "RF / Electronic Warfare" as const,
        mitre_technique: "T1498.001",
        technique_name: "RF Denial of Service",
        description: "Adversary emits high-power sweep across 161.975 MHz and 5.8 GHz SATCOM link.",
        artifact_payload: "RF_JAM_BAND=C_BAND FREQ=5850.00MHz POWER=+38dBm",
        expected_alert: "Tactical EW: SATCOM C-Band Telemetry Carrier Suppressed",
        d3fend_countermeasure_id: "D3-ECMN",
        status: "Pending" as const
      },
      {
        step_number: 2,
        name: "IEC 61850 GOOSE Trip Message Injection",
        domain: "Network / DPI" as const,
        mitre_technique: "T0855",
        technique_name: "Unauthorized Command Message",
        description: "Adversary injects spoofed GOOSE frame into substation ethernet ring.",
        artifact_payload: "GOOSE_PDU: AppID=0x0001 StNum=14 SqNum=202 DatSet=Trip_Turbine_Array",
        expected_alert: "DPI Alarm: Malformed IEC 61850 GOOSE Sequence from Untrusted MAC",
        d3fend_countermeasure_id: "D3-PRC",
        status: "Pending" as const
      },
      {
        step_number: 3,
        name: "PLC Logic Firmware Overwrite",
        domain: "Cyber" as const,
        mitre_technique: "T0857",
        technique_name: "System Firmware Modification",
        description: "Direct memory write over S7comm to flash modified pitch-control microcode.",
        artifact_payload: "S7COMM: Job=WriteVar DB=104 Offset=0x0020 Length=512",
        expected_alert: "EDR Alarm: Unauthorized S7comm Firmware Flash Attempt Detected",
        d3fend_countermeasure_id: "D3-FSI",
        status: "Pending" as const
      }
    ]
  },
  {
    name: "Military SATCOM Uplink Hijack & BGP Hijack",
    threat_actor: "APT28 / Fancy Bear",
    sector: "Aerospace & Defense SATCOM",
    category: "Stealth C2 & Active Directory" as const,
    severity: "High" as const,
    complexity: "High-Velocity Burst" as const,
    duration: 120,
    steps: [
      {
        step_number: 1,
        name: "BGP Autonomous System Route Hijack",
        domain: "Cyber" as const,
        mitre_technique: "T1584.001",
        technique_name: "Compromise Infrastructure: DNS/BGP",
        description: "Adversary announces rogue /24 prefix for Ground SATCOM Gateway IP.",
        artifact_payload: "BGP_UPDATE: Prefix=198.51.100.0/24 AS_PATH=65001 7018",
        expected_alert: "SOC Alert: Anomalous BGP AS-Path Prefix Announcement",
        d3fend_countermeasure_id: "D3-FQDN",
        status: "Pending" as const
      },
      {
        step_number: 2,
        name: "Uplink Transponder Saturation",
        domain: "RF / Electronic Warfare" as const,
        mitre_technique: "T1498.001",
        technique_name: "RF Spectral Jamming",
        description: "Adversary emits CW carrier into satellite uplink feed.",
        artifact_payload: "RF_UPLINK_FREQ=14.250GHz POWER=+45dBm MOD=CW",
        expected_alert: "Tactical EW: Transponder 3 Uplink AGC Compressed",
        d3fend_countermeasure_id: "D3-ECMN",
        status: "Pending" as const
      }
    ]
  }
];

export const CampaignStudioTab: React.FC<Props> = ({ onScenarioCreated, onNavigateToSandbox }) => {
  const [title, setTitle] = useState("Custom Multi-Domain Threat Campaign");
  const [threatActor, setThreatActor] = useState("Sandworm (APT28)");
  const [targetSector, setTargetSector] = useState("Critical Infrastructure & Energy Grid");
  const [severity, setSeverity] = useState<"Critical" | "High" | "Medium">("Critical");
  const [category, setCategory] = useState<"SCADA / Grid Blackout" | "Stealth C2 & Active Directory" | "Tactical Drone EW Incursion" | "Destructive Wiper & Financial">("SCADA / Grid Blackout");
  const [complexity, setComplexity] = useState<"Advanced Multi-Stage" | "High-Velocity Burst" | "Low & Slow Tactical">("Advanced Multi-Stage");
  const [summary, setSummary] = useState("Coordinated multi-domain offensive combining custom RF spectrum manipulation, lateral Kerberos movement, and unauthorized SCADA Modbus actuation.");
  const [durationSec, setDurationSec] = useState(150);

  const [steps, setSteps] = useState<SimulationStep[]>([
    {
      step_number: 1,
      name: "RF Spectral Recon & Beacon Intercept",
      domain: "RF / Electronic Warfare",
      mitre_technique: "T1595.002",
      technique_name: "RF Spectral Recon",
      description: "Hostile SDR sweeps 433 MHz and 1.5 GHz target telemetry channels.",
      artifact_payload: "RF_BURST_FREQ=433.920MHz POWER=-42dBm MOD=GFSK",
      expected_alert: "Tactical EW: Unauthorized Wideband RF Sweep Detected",
      d3fend_countermeasure_id: "D3-ECMN",
      status: "Pending"
    },
    {
      step_number: 2,
      name: "Active Directory Kerberoasting",
      domain: "Cyber",
      mitre_technique: "T1558.003",
      technique_name: "Kerberoasting (TGS Request)",
      description: "Adversary queries SPNs for high-privilege service accounts using RC4 cipher.",
      artifact_payload: "KRB5_TGS_REQ: ServiceName=MSSQLSvc/db01.corp Encryption=RC4-HMAC",
      expected_alert: "DPI Alarm: Suspicious Kerberos TGS RC4-HMAC Ticket Extraction",
      d3fend_countermeasure_id: "D3-KROT",
      status: "Pending"
    }
  ]);

  const [ips, setIps] = useState("192.168.10.14, 198.51.100.89");
  const [domains, setDomains] = useState("grid-update.scada-telemetry.org");
  const [frequencies, setFrequencies] = useState("433.92 MHz, 1575.42 MHz (GPS L1)");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleAddStep = () => {
    const newStep: SimulationStep = {
      step_number: steps.length + 1,
      name: `Tactical Stage ${steps.length + 1}`,
      domain: "Cyber",
      mitre_technique: "T1071.001",
      technique_name: "Web Protocols / C2",
      description: "Adversary initiates tactical action against target infrastructure.",
      artifact_payload: "CUSTOM_PAYLOAD_STAGE",
      expected_alert: "Security Alert: Detected anomalous activity",
      d3fend_countermeasure_id: "D3-PRC",
      status: "Pending"
    };
    setSteps([...steps, newStep]);
  };

  const handleRemoveStep = (index: number) => {
    const updated = steps.filter((_, i) => i !== index).map((s, i) => ({ ...s, step_number: i + 1 }));
    setSteps(updated);
  };

  const handleStepChange = (index: number, field: keyof SimulationStep, value: any) => {
    const updated = [...steps];
    updated[index] = { ...updated[index], [field]: value };
    setSteps(updated);
  };

  const handleLoadTemplate = (template: typeof TEMPLATES[0]) => {
    setTitle(template.name);
    setThreatActor(template.threat_actor);
    setTargetSector(template.sector);
    setCategory(template.category);
    setSeverity(template.severity);
    setComplexity(template.complexity);
    setDurationSec(template.duration);
    setSteps(template.steps as any);
  };

  const handleSaveCampaign = async () => {
    setSaving(true);
    setSaveSuccess(false);

    const scenarioPayload: AdversaryScenario = {
      id: `custom-${Date.now()}`,
      title,
      threat_actor: threatActor,
      target_sector: targetSector,
      severity,
      category,
      complexity,
      summary,
      estimated_duration_sec: durationSec,
      steps,
      iocs_involved: {
        ips: ips.split(",").map(s => s.trim()).filter(Boolean),
        domains: domains.split(",").map(s => s.trim()).filter(Boolean),
        hashes: ["e10adc3949ba59abbe56e057f20f883e"],
        rf_frequencies: frequencies.split(",").map(s => s.trim()).filter(Boolean)
      }
    };

    try {
      const res = await fetch("/api/studio/campaigns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scenarioPayload)
      });

      if (res.ok) {
        setSaveSuccess(true);
        if (onScenarioCreated) {
          onScenarioCreated(scenarioPayload);
        }
        setTimeout(() => setSaveSuccess(false), 4000);
      }
    } catch (err) {
      console.error("Error saving campaign:", err);
    } finally {
      setSaving(false);
    }
  };

  const handleDownloadJSON = () => {
    const scenarioPayload = {
      id: `custom-${Date.now()}`,
      title,
      threat_actor: threatActor,
      target_sector: targetSector,
      severity,
      category,
      complexity,
      summary,
      estimated_duration_sec: durationSec,
      steps,
      iocs_involved: {
        ips: ips.split(",").map(s => s.trim()).filter(Boolean),
        domains: domains.split(",").map(s => s.trim()).filter(Boolean),
        hashes: ["e10adc3949ba59abbe56e057f20f883e"],
        rf_frequencies: frequencies.split(",").map(s => s.trim()).filter(Boolean)
      }
    };

    const blob = new Blob([JSON.stringify(scenarioPayload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Campaign_${title.replace(/\s+/g, "_")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div id="campaign-studio-view" className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/30">
            <Palette className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100">
              Custom Threat Campaign Studio & Scenario Builder
            </h2>
            <p className="text-xs text-slate-400">
              Design multi-stage adversary campaigns with custom RF frequencies, Sigma payloads, and MITRE ATT&CK / D3FEND mappings.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleDownloadJSON}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export Scenario JSON
          </button>

          <button
            onClick={handleSaveCampaign}
            disabled={saving}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 shadow-lg shadow-purple-600/20 cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? "Saving..." : saveSuccess ? "Saved to Sandbox!" : "Save & Add to Sandbox"}
          </button>
        </div>
      </div>

      {/* Templates Strip */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-2">
        <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Load Pre-Configured Tactical Campaign Template:
        </span>
        <div className="flex flex-wrap gap-2">
          {TEMPLATES.map((tmpl, idx) => (
            <button
              key={idx}
              onClick={() => handleLoadTemplate(tmpl)}
              className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-2 transition-all cursor-pointer"
            >
              <span>{tmpl.name}</span>
              <span className="px-1.5 py-0.2 bg-purple-950/60 text-purple-300 rounded text-[10px]">{tmpl.threat_actor}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Campaign Metadata Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          1. Campaign Parameters & Adversary Profile
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Campaign Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
            />
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Threat Actor / Unit</label>
            <input
              type="text"
              value={threatActor}
              onChange={(e) => setThreatActor(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
            />
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Target Sector</label>
            <input
              type="text"
              value={targetSector}
              onChange={(e) => setTargetSector(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Category</label>
            <select
              value={category}
              onChange={(e: any) => setCategory(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="SCADA / Grid Blackout">SCADA / Grid Blackout</option>
              <option value="Stealth C2 & Active Directory">Stealth C2 & Active Directory</option>
              <option value="Tactical Drone EW Incursion">Tactical Drone EW Incursion</option>
              <option value="Destructive Wiper & Financial">Destructive Wiper & Financial</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e: any) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Complexity</label>
            <select
              value={complexity}
              onChange={(e: any) => setComplexity(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="Advanced Multi-Stage">Advanced Multi-Stage</option>
              <option value="High-Velocity Burst">High-Velocity Burst</option>
              <option value="Low & Slow Tactical">Low & Slow Tactical</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Duration (Seconds)</label>
            <input
              type="number"
              value={durationSec}
              onChange={(e) => setDurationSec(parseInt(e.target.value) || 60)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
            />
          </div>
        </div>

        <div>
          <label className="text-xs font-mono text-slate-400 block mb-1">Operational Summary</label>
          <textarea
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
          />
        </div>

        {/* Indicators of Compromise (IoCs) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800">
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">Involved IPs</label>
            <input
              type="text"
              value={ips}
              onChange={(e) => setIps(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">C2 Domains</label>
            <input
              type="text"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1">RF Frequencies</label>
            <input
              type="text"
              value={frequencies}
              onChange={(e) => setFrequencies(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      {/* Multi-Stage Orchestrator */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            2. Multi-Domain Attack Stages ({steps.length})
          </h3>

          <button
            onClick={handleAddStep}
            className="px-3 py-1.5 bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/40 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Stage
          </button>
        </div>

        <div className="space-y-4">
          {steps.map((step, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-xs font-mono font-bold">
                    Stage {step.step_number}
                  </span>
                  <input
                    type="text"
                    value={step.name}
                    onChange={(e) => handleStepChange(idx, "name", e.target.value)}
                    className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={step.domain}
                    onChange={(e: any) => handleStepChange(idx, "domain", e.target.value)}
                    className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-200 cursor-pointer"
                  >
                    <option value="Cyber">Cyber</option>
                    <option value="RF / Electronic Warfare">RF / Electronic Warfare</option>
                    <option value="Physical / GIS">Physical / GIS</option>
                    <option value="Network / DPI">Network / DPI</option>
                  </select>

                  {steps.length > 1 && (
                    <button
                      onClick={() => handleRemoveStep(idx)}
                      className="p-1 text-red-400 hover:text-red-300 hover:bg-red-950/40 rounded cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="text-[10px] font-mono text-slate-400 block mb-1">MITRE Technique ID</label>
                  <input
                    type="text"
                    value={step.mitre_technique}
                    onChange={(e) => handleStepChange(idx, "mitre_technique", e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-400 block mb-1">Technique Name</label>
                  <input
                    type="text"
                    value={step.technique_name}
                    onChange={(e) => handleStepChange(idx, "technique_name", e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-400 block mb-1">D3FEND Countermeasure ID</label>
                  <input
                    type="text"
                    value={step.d3fend_countermeasure_id || ""}
                    onChange={(e) => handleStepChange(idx, "d3fend_countermeasure_id", e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="text-[10px] font-mono text-slate-400 block mb-1">Artifact Payload / Command / Burst</label>
                  <input
                    type="text"
                    value={step.artifact_payload}
                    onChange={(e) => handleStepChange(idx, "artifact_payload", e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-amber-300 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-400 block mb-1">Expected Detection / Alert Message</label>
                  <input
                    type="text"
                    value={step.expected_alert}
                    onChange={(e) => handleStepChange(idx, "expected_alert", e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-cyan-300 focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
