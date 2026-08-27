import React, { useState, useEffect } from "react";
import { AttackPathNode, AttackPathEdge, ForensicReport } from "../../types";
import {
  GitCommit,
  ShieldAlert,
  Download,
  FileText,
  Layers,
  Activity,
  ArrowRight,
  UserCheck,
  Server,
  Key,
  Database,
  Globe,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ExternalLink,
  RefreshCw,
  Clock,
  Briefcase,
} from "lucide-react";

export const AttackPathForensicsTab: React.FC = () => {
  const [nodes, setNodes] = useState<AttackPathNode[]>([]);
  const [edges, setEdges] = useState<AttackPathEdge[]>([]);
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackPathNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<AttackPathEdge | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [activeSubView, setActiveSubView] = useState<"graph" | "report">("graph");

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [graphRes, reportRes] = await Promise.all([
        fetch("/api/forensics/attack-path").then(r => r.json()),
        fetch("/api/forensics/report").then(r => r.json()),
      ]);
      if (graphRes.nodes) {
        setNodes(graphRes.nodes);
        setSelectedNode(graphRes.nodes[1] || graphRes.nodes[0]);
      }
      if (graphRes.edges) setEdges(graphRes.edges);
      if (reportRes) setReport(reportRes);
    } catch (e) {
      console.error("Error loading forensics & graph:", e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const downloadReportMarkdown = () => {
    if (!report) return;
    const md = `# ${report.incident_title}
**Report ID**: ${report.report_id}
**Generated**: ${report.generated_at}
**Severity**: ${report.severity}
**Threat Actor**: ${report.threat_actor}
**Status**: ${report.status}

---

## 1. Executive Summary
${report.executive_summary}

---

## 2. Impact Assessment
- **Affected Hosts**: ${report.impact_assessment.affected_hosts}
- **Compromised Accounts**: ${report.impact_assessment.compromised_accounts}
- **Exfiltrated Telemetry**: ${report.impact_assessment.exfiltrated_data_mb} MB
- **Downtime / Interruption**: ${report.impact_assessment.business_interruption_hours} Hours

---

## 3. MITRE ATT&CK Kill Chain Alignment
${report.mitre_coverage.map(m => `### ${m.phase}: [${m.technique_id}] ${m.technique_name}\n- **Evidence**: ${m.evidence}\n`).join("\n")}

---

## 4. Key Indicators of Compromise (IOCs)
${report.key_iocs.map(i => `- **[${i.type.toUpperCase()}]** \`${i.value}\` (Confidence: ${(i.confidence * 100).toFixed(0)}%) - ${i.context}`).join("\n")}

---

## 5. Containment Actions Taken
${report.containment_actions_taken.map(c => `- [x] ${c}`).join("\n")}

---

## 6. Strategic Recommendations
${report.recommendations.map(r => `- ${r}`).join("\n")}
`;

    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Forensic_Report_${report.report_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "c2_server":
        return <Globe className="w-4 h-4 text-rose-400" />;
      case "host":
        return <Server className="w-4 h-4 text-amber-400" />;
      case "user":
      case "credential":
        return <Key className="w-4 h-4 text-purple-400" />;
      case "crown_jewel":
        return <Database className="w-4 h-4 text-cyan-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Tab Header Controls */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-semibold text-[#e8edf2]">
              Interactive Attack Path Graph & Forensic Incident Reporting
            </h3>
          </div>
          <p className="text-xs text-[#94a3b8] mt-1">
            Reconstructed kill-chain graph showing lateral movement hops, privilege escalation bridges, and executive briefing dossiers
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded-lg bg-[#151e29] p-1 border border-[#243244]">
            <button
              onClick={() => setActiveSubView("graph")}
              className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
                activeSubView === "graph"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-[#94a3b8] hover:text-[#e8edf2]"
              }`}
            >
              <GitCommit className="w-3.5 h-3.5" />
              <span>Attack Path Graph</span>
            </button>
            <button
              onClick={() => setActiveSubView("report")}
              className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
                activeSubView === "report"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-[#94a3b8] hover:text-[#e8edf2]"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Forensic Briefing Report</span>
            </button>
          </div>

          <button
            onClick={fetchData}
            className="p-2 rounded-lg bg-[#151e29] hover:bg-[#1e2a3b] border border-[#243244] text-[#94a3b8] hover:text-[#e8edf2] transition-colors"
            title="Refresh Analysis"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          {activeSubView === "report" && (
            <button
              onClick={downloadReportMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Report (.md)</span>
            </button>
          )}
        </div>
      </div>

      {/* VIEW 1: INTERACTIVE ATTACK PATH GRAPH */}
      {activeSubView === "graph" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Main Visual Kill Chain Sequence Canvas */}
          <div className="lg:col-span-2 p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Kill Chain Traversal Sequence ({nodes.length} Nodes, {edges.length} Transitions)
              </h4>
              <span className="text-[11px] font-mono text-cyan-300">Target: Domain Controller Core</span>
            </div>

            {/* Visual Node & Edge Flow Progression */}
            <div className="space-y-3 p-3 rounded-lg bg-[#0b0f14] border border-[#243244] overflow-x-auto">
              <div className="flex items-center gap-2 min-w-[620px] justify-between">
                {nodes.map((node, i) => {
                  const isSelected = selectedNode?.id === node.id;
                  return (
                    <React.Fragment key={node.id}>
                      <div
                        onClick={() => {
                          setSelectedNode(node);
                          setSelectedEdge(null);
                        }}
                        className={`flex-1 p-3 rounded-lg border transition-all cursor-pointer text-center relative ${
                          isSelected
                            ? "bg-cyan-950/60 border-cyan-400 shadow-md ring-1 ring-cyan-400/40"
                            : node.compromised
                            ? "bg-[#151e29] border-rose-900/60 hover:border-rose-700"
                            : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
                        }`}
                      >
                        <div className="flex justify-center mb-1.5">
                          <div
                            className={`p-2 rounded-full ${
                              node.type === "c2_server"
                                ? "bg-rose-950 border border-rose-800"
                                : node.type === "crown_jewel"
                                ? "bg-cyan-950 border border-cyan-800"
                                : "bg-[#111821] border border-[#243244]"
                            }`}
                          >
                            {getNodeIcon(node.type)}
                          </div>
                        </div>

                        <div className="font-mono text-xs font-bold text-[#e8edf2] truncate">
                          {node.label.split("(")[0]}
                        </div>
                        <div className="text-[10px] text-[#94a3b8] font-mono mt-0.5 truncate">
                          {node.ip || node.user}
                        </div>

                        <div className="mt-2 flex items-center justify-center gap-1">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase ${
                              node.compromised
                                ? "bg-rose-950 text-rose-300 border border-rose-800"
                                : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                            }`}
                          >
                            {node.compromised ? "Compromised" : "Target"}
                          </span>
                        </div>
                      </div>

                      {i < nodes.length - 1 && (
                        <div
                          onClick={() => {
                            setSelectedEdge(edges[i] || null);
                            setSelectedNode(null);
                          }}
                          className="flex flex-col items-center justify-center px-1 cursor-pointer group"
                        >
                          <div className="text-[9px] font-mono text-cyan-400 group-hover:text-cyan-300">
                            Hop {i + 1}
                          </div>
                          <ArrowRight className="w-4 h-4 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Edge Lateral Movement Transitions Table */}
            <div className="space-y-2">
              <h5 className="text-xs font-semibold text-[#e8edf2] flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-amber-400" />
                Lateral Movement & Traversal Transitions
              </h5>
              <div className="space-y-1.5">
                {edges.map((edge, idx) => {
                  const isSelected = selectedEdge?.id === edge.id;
                  const sourceNode = nodes.find(n => n.id === edge.source);
                  const targetNode = nodes.find(n => n.id === edge.target);

                  return (
                    <div
                      key={edge.id}
                      onClick={() => {
                        setSelectedEdge(edge);
                        setSelectedNode(null);
                      }}
                      className={`p-2.5 rounded-lg border transition-all cursor-pointer text-xs ${
                        isSelected
                          ? "bg-cyan-950/40 border-cyan-500"
                          : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                            {edge.tactic}
                          </span>
                          <span className="font-semibold text-[#e8edf2]">{edge.technique}</span>
                        </div>
                        <span className="text-[10px] font-mono text-[#94a3b8]">{edge.protocol}</span>
                      </div>
                      <p className="text-[11px] text-[#94a3b8] mt-1">{edge.description}</p>
                      <div className="flex items-center justify-between text-[10px] text-[#64748b] mt-1 pt-1 border-t border-[#243244]/60">
                        <span>
                          {sourceNode?.label.split("(")[0]} &rarr; {targetNode?.label.split("(")[0]}
                        </span>
                        <span>Confidence: {(edge.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Node / Edge Deep Inspector Panel */}
          <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Graph Entity & Hop Inspector
            </h4>

            {selectedNode && (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#e8edf2]">{selectedNode.label}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        selectedNode.risk_score > 0.8 ? "bg-rose-950 text-rose-300" : "bg-amber-950 text-amber-300"
                      }`}
                    >
                      Score: {selectedNode.risk_score}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] text-[#94a3b8]">
                    <div>
                      <span className="block text-[10px] text-[#64748b]">Entity Type:</span>
                      <span className="capitalize font-mono text-[#e8edf2]">{selectedNode.type}</span>
                    </div>
                    <div>
                      <span className="block text-[10px] text-[#64748b]">Network Tier:</span>
                      <span className="capitalize font-mono text-[#e8edf2]">{selectedNode.tier}</span>
                    </div>
                    {selectedNode.ip && (
                      <div>
                        <span className="block text-[10px] text-[#64748b]">IP Address:</span>
                        <span className="font-mono text-[#e8edf2]">{selectedNode.ip}</span>
                      </div>
                    )}
                    {selectedNode.user && (
                      <div>
                        <span className="block text-[10px] text-[#64748b]">Account Context:</span>
                        <span className="font-mono text-[#e8edf2]">{selectedNode.user}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <span className="text-[11px] font-semibold text-[#e8edf2] block">
                    Observed ATT&CK Techniques:
                  </span>
                  <div className="space-y-1">
                    {selectedNode.techniques.map((t, idx) => (
                      <div
                        key={idx}
                        className="p-1.5 rounded bg-[#151e29] border border-[#243244] text-[11px] font-mono text-cyan-300 flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                        <span>{t}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#0b0f14] border border-[#243244] space-y-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-[#94a3b8] block">
                    Recommended Containment:
                  </span>
                  <div className="text-[11px] text-[#94a3b8] space-y-1">
                    <div>&bull; Issue SOAR PB-001 micro-segmentation isolation</div>
                    <div>&bull; Invalidate Kerberos session tickets and active NTLM hashes</div>
                    <div>&bull; Collect memory dump & forensic disk artifact triage</div>
                  </div>
                </div>
              </div>
            )}

            {selectedEdge && (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244] space-y-2">
                  <div className="font-bold text-[#e8edf2]">{selectedEdge.technique}</div>
                  <div className="text-[11px] text-[#94a3b8]">{selectedEdge.description}</div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-[#94a3b8] pt-2 border-t border-[#243244]/60">
                    <div>
                      <span className="block text-[10px] text-[#64748b]">Tactic Stage:</span>
                      <span className="font-semibold text-cyan-300">{selectedEdge.tactic}</span>
                    </div>
                    <div>
                      <span className="block text-[10px] text-[#64748b]">Protocol:</span>
                      <span className="font-mono text-[#e8edf2]">{selectedEdge.protocol}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: FORENSIC BRIEFING REPORT */}
      {activeSubView === "report" && report && (
        <div className="p-5 rounded-lg bg-[#111821] border border-[#243244] space-y-6 text-xs leading-relaxed max-w-5xl mx-auto">
          {/* Executive Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-[#243244]">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 uppercase">
                  {report.severity} Severity
                </span>
                <span className="text-xs font-mono text-[#94a3b8]">{report.report_id}</span>
              </div>
              <h2 className="text-lg font-bold text-[#e8edf2] mt-1">{report.incident_title}</h2>
              <div className="flex items-center gap-3 text-xs text-[#94a3b8] mt-1">
                <span>Threat Actor: <strong className="text-cyan-300">{report.threat_actor}</strong></span>
                <span>&bull;</span>
                <span>Status: <strong className="text-emerald-400">{report.status}</strong></span>
              </div>
            </div>

            <button
              onClick={downloadReportMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold shadow transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Markdown Report</span>
            </button>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              1. Executive Summary
            </h4>
            <div className="p-3.5 rounded-lg bg-[#151e29] border border-[#243244] text-[#e8edf2] text-xs leading-relaxed">
              {report.executive_summary}
            </div>
          </div>

          {/* Section 2: Impact Assessment Metrics */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              2. Forensic Impact Metrics
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244]">
                <span className="text-[10px] text-[#94a3b8] block">Affected Hosts:</span>
                <span className="font-mono text-base font-bold text-rose-400">
                  {report.impact_assessment.affected_hosts}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244]">
                <span className="text-[10px] text-[#94a3b8] block">Compromised Accounts:</span>
                <span className="font-mono text-base font-bold text-purple-400">
                  {report.impact_assessment.compromised_accounts}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244]">
                <span className="text-[10px] text-[#94a3b8] block">Exfiltrated Data:</span>
                <span className="font-mono text-base font-bold text-amber-400">
                  {report.impact_assessment.exfiltrated_data_mb} MB
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#151e29] border border-[#243244]">
                <span className="text-[10px] text-[#94a3b8] block">Business Interruption:</span>
                <span className="font-mono text-base font-bold text-emerald-400">
                  {report.impact_assessment.business_interruption_hours}h
                </span>
              </div>
            </div>
          </div>

          {/* Section 3: MITRE ATT&CK Kill Chain Breakdown */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              3. MITRE ATT&CK Matrix Kill Chain Evidence
            </h4>
            <div className="space-y-2">
              {report.mitre_coverage.map((m, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-[#151e29] border border-[#243244] text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-[#e8edf2]">
                      [{m.phase}] {m.technique_id} - {m.technique_name}
                    </span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                      Confirmed
                    </span>
                  </div>
                  <p className="text-[11px] text-[#94a3b8]">{m.evidence}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Section 4: Key IOCs */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              4. Key Indicators of Compromise (IOCs)
            </h4>
            <div className="space-y-1.5">
              {report.key_iocs.map((ioc, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-[#151e29] border border-[#243244] flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-[#111821] text-cyan-300 border border-[#243244]">
                      {ioc.type}
                    </span>
                    <span className="font-mono text-[#e8edf2] font-semibold">{ioc.value}</span>
                  </div>
                  <span className="text-[11px] text-[#94a3b8]">{ioc.context}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 5: Containment Actions & Strategic Recommendations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="p-3.5 rounded-lg bg-[#151e29] border border-[#243244] space-y-2">
              <h4 className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Containment Actions Executed
              </h4>
              <div className="space-y-1 text-[11px] text-[#94a3b8]">
                {report.containment_actions_taken.map((act, idx) => (
                  <div key={idx} className="flex items-start gap-1.5">
                    <span className="text-emerald-400">&bull;</span>
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#151e29] border border-[#243244] space-y-2">
              <h4 className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" />
                Strategic Recommendations
              </h4>
              <div className="space-y-1 text-[11px] text-[#94a3b8]">
                {report.recommendations.map((rec, idx) => (
                  <div key={idx} className="flex items-start gap-1.5">
                    <span className="text-cyan-400">&bull;</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
