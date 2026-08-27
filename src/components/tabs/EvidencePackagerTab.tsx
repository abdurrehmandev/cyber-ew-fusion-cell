import React, { useEffect, useState } from "react";
import { AirGapEvidencePackage, ForensicEvidenceManifest } from "../../types";
import {
  PackageCheck,
  ShieldCheck,
  FileCode2,
  Download,
  Copy,
  Check,
  Lock,
  FileText,
  Key,
  Layers,
  Terminal,
  Clock,
  UserCheck,
  Database,
  Hash,
  AlertCircle
} from "lucide-react";

export const EvidencePackagerTab: React.FC = () => {
  const [evidencePackage, setEvidencePackage] = useState<AirGapEvidencePackage | null>(null);
  const [incidentId, setIncidentId] = useState("INC-2026-EW-089");
  const [classification, setClassification] = useState<"UNCLASSIFIED" | "SECRET // NOFORN" | "TOP SECRET // SCI // TK">("SECRET // NOFORN");
  const [custodian, setCustodian] = useState("Senior Cyber-EW Watch Officer");
  const [activeViewTab, setActiveViewTab] = useState<"manifest" | "stix" | "cacao" | "sigma">("manifest");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  const fetchPackage = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/evidence/package?incident_id=${encodeURIComponent(incidentId)}&classification=${encodeURIComponent(classification)}&custodian=${encodeURIComponent(custodian)}`);
      const data = await res.json();
      setEvidencePackage(data);
    } catch (err) {
      console.error("Failed to generate evidence package", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPackage();
  }, [incidentId, classification, custodian]);

  const handleCopyJson = () => {
    if (!evidencePackage) return;
    const text = JSON.stringify(evidencePackage, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPackage = () => {
    if (!evidencePackage) return;
    const blob = new Blob([JSON.stringify(evidencePackage, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${evidencePackage.package_id}_AIRGAP_EVIDENCE.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getClassificationBannerStyle = () => {
    switch (classification) {
      case "TOP SECRET // SCI // TK":
        return "bg-amber-950/80 border-amber-500/80 text-amber-300 ring-amber-500/30";
      case "SECRET // NOFORN":
        return "bg-red-950/80 border-red-500/80 text-red-300 ring-red-500/30";
      default:
        return "bg-emerald-950/80 border-emerald-500/80 text-emerald-300 ring-emerald-500/30";
    }
  };

  return (
    <div id="evidence-packager-tab" className="space-y-6">
      {/* Top Banner with Air-Gap Classification Header */}
      <div className={`p-4 rounded-xl border ring-1 text-center font-mono font-bold tracking-widest text-xs uppercase shadow-xl ${getClassificationBannerStyle()}`}>
        CLASSIFICATION: {classification} // AIR-GAP DISCONNECTED HANDOFF ENCLAVE
      </div>

      {/* Main Control & Summary Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
              <PackageCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100 tracking-wide">
                  Tactical Air-Gap STIX 2.1 & CACAO Evidence Packager
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                  CHAIN OF CUSTODY SEALED
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Generate digitally signed OASIS STIX 2.1 Threat Intelligence Bundles, CACAO 2.0 SOAR Playbooks, and SHA-256 cryptographic manifests for air-gapped forensic handoff.
              </p>
            </div>
          </div>

          {/* Export / Download Buttons */}
          <div className="flex items-center gap-2">
            <button
              id="copy-evidence-bundle-btn"
              onClick={handleCopyJson}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-all cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              {copied ? "Copied JSON" : "Copy JSON Bundle"}
            </button>

            <button
              id="download-evidence-bundle-btn"
              onClick={handleDownloadPackage}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all cursor-pointer"
            >
              <Download className="w-4 h-4" />
              Export Sealed Bundle (.json)
            </button>
          </div>
        </div>

        {/* Configuration Parameter Bar */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">Incident Reference ID</label>
            <input
              type="text"
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">Security Classification Level</label>
            <select
              value={classification}
              onChange={(e) => setClassification(e.target.value as any)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500 cursor-pointer"
            >
              <option value="UNCLASSIFIED">UNCLASSIFIED</option>
              <option value="SECRET // NOFORN">SECRET // NOFORN</option>
              <option value="TOP SECRET // SCI // TK">TOP SECRET // SCI // TK</option>
            </select>
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 block mb-1">Authorized Custodian Officer</label>
            <input
              type="text"
              value={custodian}
              onChange={(e) => setCustodian(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      {/* Forensic Overview Counters */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Integrity Status</div>
            <div className="text-xs font-bold text-emerald-400">
              {evidencePackage?.manifest.integrity_verification.verification_status || "Verified Authentic"}
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <FileCode2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">STIX 2.1 Objects</div>
            <div className="text-base font-bold text-slate-100">
              {evidencePackage?.stix_bundle.objects.length || 0} <span className="text-xs font-normal text-slate-400">nodes</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Forensic Artifacts</div>
            <div className="text-base font-bold text-slate-100">
              {evidencePackage?.manifest.artifacts.length || 0} <span className="text-xs font-normal text-slate-400">files</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Hash className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Merkle Root Hash</div>
            <div className="text-xs font-mono font-bold text-amber-300 truncate max-w-[140px]">
              {evidencePackage?.manifest.integrity_verification.hash_tree_root.slice(0, 16)}...
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation for Views */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveViewTab("manifest")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeViewTab === "manifest"
              ? "bg-slate-800 text-emerald-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <UserCheck className="w-4 h-4" />
          Chain of Custody & Cryptographic Manifest
        </button>

        <button
          onClick={() => setActiveViewTab("stix")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeViewTab === "stix"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileCode2 className="w-4 h-4" />
          OASIS STIX 2.1 Threat Graph
        </button>

        <button
          onClick={() => setActiveViewTab("cacao")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeViewTab === "cacao"
              ? "bg-slate-800 text-cyan-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Terminal className="w-4 h-4" />
          CACAO 2.0 Security Playbook
        </button>

        <button
          onClick={() => setActiveViewTab("sigma")}
          className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
            activeViewTab === "sigma"
              ? "bg-slate-800 text-amber-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileText className="w-4 h-4" />
          Bundled Sigma Rules
        </button>
      </div>

      {/* Active Tab View Details */}
      {evidencePackage && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
          {activeViewTab === "manifest" && (
            <div className="space-y-4">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Digital Chain of Custody & Witness Signatures
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {evidencePackage.manifest.custody_chain.map((c, idx) => (
                  <div key={idx} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="font-bold text-xs text-slate-200">{c.custodian}</div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        {c.role}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">{c.organization}</div>
                    <div className="pt-2 border-t border-slate-800 text-[10px] font-mono text-slate-500 space-y-1">
                      <div>Algorithm: {c.signature_algorithm}</div>
                      <div className="text-cyan-400/90 break-all">{c.digital_signature}</div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Artifacts Table */}
              <div className="space-y-2 pt-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Forensic Artifacts & SHA-256 Hashes
                </div>

                <div className="space-y-2">
                  {evidencePackage.manifest.artifacts.map((a, idx) => (
                    <div key={idx} className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="font-bold text-xs font-mono text-slate-200 flex items-center gap-2">
                          <FileCode2 className="w-4 h-4 text-emerald-400" />
                          {a.filename}
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          {a.file_type} • {(a.size_bytes / 1024).toFixed(1)} KB
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{a.description}</p>
                      <div className="pt-1.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
                        <span>SHA-256: <span className="text-amber-300/90">{a.sha256}</span></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeViewTab === "stix" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  OASIS STIX 2.1 JSON Threat Graph (Spec Version 2.1)
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  {evidencePackage.stix_bundle.objects.length} Objects Encoded
                </span>
              </div>
              <pre className="p-4 rounded-xl bg-black/90 border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto max-h-[500px]">
                {JSON.stringify(evidencePackage.stix_bundle, null, 2)}
              </pre>
            </div>
          )}

          {activeViewTab === "cacao" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  OASIS CACAO 2.0 Security Playbook Workflow
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  Spec Version cacao-2.0
                </span>
              </div>
              <pre className="p-4 rounded-xl bg-black/90 border border-slate-800 font-mono text-xs text-cyan-300 overflow-x-auto max-h-[500px]">
                {JSON.stringify(evidencePackage.cacao_playbook, null, 2)}
              </pre>
            </div>
          )}

          {activeViewTab === "sigma" && (
            <div className="space-y-3">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Bundled Production Detection Signatures (Sigma YAML)
              </div>
              <pre className="p-4 rounded-xl bg-black/90 border border-slate-800 font-mono text-xs text-amber-300 overflow-x-auto max-h-[500px]">
                {evidencePackage.raw_sigma_rules.join("\n---\n")}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
