import React, { useState, useEffect } from "react";
import {
  FileText,
  Shield,
  Download,
  Copy,
  Printer,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Zap,
  Activity,
  Radio,
  Server,
  DollarSign,
  Clock,
  ChevronDown,
  ChevronRight,
  RefreshCw
} from "lucide-react";
import { TacticalSitrepReport } from "../../types";

export const SitrepGeneratorTab: React.FC = () => {
  const [report, setReport] = useState<TacticalSitrepReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [classification, setClassification] = useState<"UNCLASSIFIED" | "SECRET // NOFORN" | "TOP SECRET // SCI // TK">("SECRET // NOFORN");
  const [reportingUnit, setReportingUnit] = useState("Joint Tactical Cyber-EW Fusion Taskforce (CTF-71)");
  const [copied, setCopied] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    "1. SITUATION": true,
    "2. MISSION": true,
    "3. EXECUTION": true,
    "4. ADMINISTRATION & LOGISTICS": true,
    "5. COMMAND & SIGNAL": true
  });

  const fetchSitrep = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/reports/sitrep?classification=${encodeURIComponent(classification)}&reporting_unit=${encodeURIComponent(reportingUnit)}`);
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      }
    } catch (err) {
      console.error("Error fetching SITREP report:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSitrep();
  }, [classification]);

  const toggleSection = (sectionKey: string) => {
    setExpandedSections(prev => ({ ...prev, [sectionKey]: !prev[sectionKey] }));
  };

  const handleCopyMarkdown = () => {
    if (!report) return;
    let md = `# [${report.classification}] TACTICAL SITUATION REPORT (SITREP)\n`;
    md += `**REPORT ID:** ${report.report_id}\n`;
    md += `**DTG:** ${report.dtg_military_timestamp}\n`;
    md += `**OPERATION:** ${report.operation_codename}\n`;
    md += `**REPORTING UNIT:** ${report.reporting_unit}\n\n`;
    md += `## EXECUTIVE SUMMARY\n${report.executive_summary}\n\n`;
    md += `## DAMAGE ASSESSMENT MATRIX\n`;
    md += `- **Compromised Endpoints:** ${report.damage_assessment.compromised_endpoints_count}\n`;
    md += `- **Active Directory Risk:** ${report.damage_assessment.active_directory_domain_risk}\n`;
    md += `- **SCADA Substation Status:** ${report.damage_assessment.scada_substation_status}\n`;
    md += `- **Grid Capacity Impact:** ${report.damage_assessment.grid_capacity_impact_mw} MW\n`;
    md += `- **Estimated Financial Impact:** $${report.damage_assessment.financial_impact_est_usd.toLocaleString()}\n`;
    md += `- **Threat Containment:** ${report.damage_assessment.threat_containment_pct}%\n\n`;

    report.sections.forEach(sec => {
      md += `## ${sec.paragraph_number} ${sec.title}\n`;
      sec.subsections.forEach(sub => {
        md += `### ${sub.subtitle}\n${sub.content}\n\n`;
        if (sub.key_bullet_points) {
          sub.key_bullet_points.forEach(b => {
            md += `- ${b}\n`;
          });
          md += `\n`;
        }
      });
    });

    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  const handleDownloadMarkdown = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SITREP_${report.incident_id}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintReport = () => {
    window.print();
  };

  return (
    <div id="sitrep-generator-view" className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-slate-100">
                Automated Adversary Threat Briefing & NATO 5-Paragraph SITREP
              </h2>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${
                (classification || "").includes("TOP SECRET")
                  ? "bg-purple-950/60 text-purple-300 border-purple-800"
                  : (classification || "").includes("SECRET")
                  ? "bg-red-950/60 text-red-300 border-red-800"
                  : "bg-emerald-950/60 text-emerald-300 border-emerald-800"
              }`}>
                {classification || "UNCLASSIFIED"}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              One-click standardized field situation report adhering to NATO STANAG 2014 / DoD JP 3-13.1 Cyber-EW operational doctrine.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={classification}
            onChange={(e: any) => setClassification(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500 cursor-pointer"
          >
            <option value="SECRET // NOFORN">SECRET // NOFORN</option>
            <option value="TOP SECRET // SCI // TK">TOP SECRET // SCI // TK</option>
            <option value="UNCLASSIFIED">UNCLASSIFIED</option>
          </select>

          <button
            onClick={fetchSitrep}
            disabled={loading}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Regenerate
          </button>

          <button
            onClick={handleCopyMarkdown}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <Copy className="w-3.5 h-3.5 text-cyan-400" />
            {copied ? "Copied Field MD!" : "Copy Dispatch"}
          </button>

          <button
            onClick={handleDownloadMarkdown}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            Export JSON
          </button>

          <button
            onClick={handlePrintReport}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 shadow-lg shadow-amber-600/20 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Field Order
          </button>
        </div>
      </div>

      {report && (
        <div className="space-y-6">
          {/* Military Header Strip */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">DATE-TIME GROUP (DTG)</span>
                <span className="text-amber-400 font-bold text-sm">{report.dtg_military_timestamp}</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">OPERATION CODENAME</span>
                <span className="text-slate-100 font-bold text-sm">{report.operation_codename}</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">INCIDENT TRACKING ID</span>
                <span className="text-cyan-400 font-bold text-sm">{report.incident_id}</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">PRIMARY THREAT ACTOR</span>
                <span className="text-red-400 font-bold text-sm truncate">{report.threat_actor}</span>
              </div>
            </div>

            {/* Executive Summary Callout */}
            <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-amber-400">
                <Sparkles className="w-4 h-4" />
                EXECUTIVE SUMMARY & OPERATIONAL DISPATCH
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {report.executive_summary}
              </p>
            </div>
          </div>

          {/* Damage Assessment Matrix */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-400" />
              Tactical & Operational Damage Assessment Matrix
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">COMPROMISED HOSTS</span>
                <span className="text-xl font-bold font-mono text-red-400">{report.damage_assessment.compromised_endpoints_count} Endpoints</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">AD DOMAIN RISK</span>
                <span className="text-xl font-bold font-mono text-amber-400">{report.damage_assessment.active_directory_domain_risk}</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">GRID IMPACT</span>
                <span className="text-xl font-bold font-mono text-cyan-400">{report.damage_assessment.grid_capacity_impact_mw} MW</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">SCADA SUBSTATION</span>
                <span className="text-xl font-bold font-mono text-emerald-400">{report.damage_assessment.scada_substation_status}</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">EST. LOSS</span>
                <span className="text-xl font-bold font-mono text-slate-200">${(report.damage_assessment.financial_impact_est_usd / 1000000).toFixed(2)}M</span>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 block">CONTAINMENT EFF.</span>
                <span className="text-xl font-bold font-mono text-emerald-400">{report.damage_assessment.threat_containment_pct}%</span>
              </div>
            </div>
          </div>

          {/* The 5 Paragraphs Accordion */}
          <div className="space-y-4">
            {report.sections.map((section) => {
              const isExpanded = expandedSections[section.paragraph_number] ?? true;
              return (
                <div
                  key={section.paragraph_number}
                  className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg transition-all"
                >
                  <button
                    onClick={() => toggleSection(section.paragraph_number)}
                    className="w-full px-5 py-4 flex items-center justify-between bg-slate-900/80 hover:bg-slate-800/60 text-left border-b border-slate-800/80 cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <span className="px-2.5 py-1 bg-slate-800 rounded text-xs font-mono font-bold text-amber-400">
                        {section.paragraph_number}
                      </span>
                      <span className="text-sm font-bold text-slate-100">
                        {section.title}
                      </span>
                    </div>
                    {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                  </button>

                  {isExpanded && (
                    <div className="p-5 space-y-5 bg-slate-950/50">
                      {section.subsections.map((sub, idx) => (
                        <div key={idx} className="space-y-2">
                          <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                            {sub.subtitle}
                          </h4>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {sub.content}
                          </p>
                          {sub.key_bullet_points && sub.key_bullet_points.length > 0 && (
                            <ul className="space-y-1.5 pt-1">
                              {sub.key_bullet_points.map((pt, pIdx) => (
                                <li key={pIdx} className="text-xs text-slate-300 flex items-start gap-2">
                                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                                  <span>{pt}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
