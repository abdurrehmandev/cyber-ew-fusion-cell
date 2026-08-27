import React, { useState } from "react";
import {
  Terminal,
  Play,
  Database,
  Download,
  CheckCircle2,
  Sparkles,
  Shield,
  FileCode2,
  Workflow,
  Cpu,
  Copy,
  Check,
  Zap,
  ArrowRight,
} from "lucide-react";
import { AIHuntingResponse } from "../../types";

export const HuntingTab: React.FC = () => {
  // KQL State
  const [query, setQuery] = useState("alerts | where score >= 0.7 | take 50");
  const [limit, setLimit] = useState(50);
  const [isRunning, setIsRunning] = useState(false);
  const [queryResult, setQueryResult] = useState<{
    row_count: number;
    elapsed_ms: number;
    rows: any[];
  } | null>(null);
  const [lakeSnapshotStatus, setLakeSnapshotStatus] = useState<string | null>(null);

  // AI Hunting State
  const [aiPrompt, setAiPrompt] = useState(
    "Hunt for Kerberoasting SPN ticket requests utilizing anomalous RC4-HMAC encryption and Cobalt Strike C2 jitter beacons"
  );
  const [selectedTech, setSelectedTech] = useState("T1558.003");
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [aiResult, setAiResult] = useState<AIHuntingResponse | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [deployedStatus, setDeployedStatus] = useState<string | null>(null);

  const sampleQueries = [
    { name: "High Severity Alerts", kql: "alerts | where score >= 0.8 | take 50" },
    { name: "Ransomware Operations", kql: "alerts | where patterns contains 'ransomware' | take 50" },
    { name: "C2 Callback Activity", kql: "alerts | where patterns contains 'c2' | take 50" },
    { name: "Authentication Anomalies", kql: "alerts | where event_type == 'authentication' | take 50" },
  ];

  const quickHuntTechniques = [
    { id: "T1558.003", name: "Kerberoasting (T1558.003)", prompt: "Hunt for Kerberoasting service ticket requests utilizing weak RC4-HMAC cipher suites against high-value SPNs." },
    { id: "T1071.001", name: "Cobalt Strike HTTPS C2 (T1071.001)", prompt: "Hunt for Cobalt Strike malleable HTTPS beacons with periodic jitter and specific JA3 TLS fingerprints." },
    { id: "T1005", name: "RF-to-Cyber C2 Exfil (T1005 / EW)", prompt: "Hunt for cross-domain covert RF SDR emissions paired with local NTP clock skew and lateral data exfiltration." },
    { id: "T1021.002", name: "SMB/WMI Lateral Spread (T1021.002)", prompt: "Hunt for remote service execution via PsExec, WMI Win32_Process, and administrative share writes (C$, ADMIN$)." },
  ];

  const handleRunQuery = async () => {
    setIsRunning(true);
    try {
      const res = await fetch("/api/hunt/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, limit }),
      });
      const data = await res.json();
      setQueryResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleCreateSnapshot = async () => {
    try {
      const res = await fetch("/api/lake/snapshot", { method: "POST" });
      const data = await res.json();
      setLakeSnapshotStatus(`Lake snapshot written: ${data.snapshot_id} (${data.exported_records} records)`);
      setTimeout(() => setLakeSnapshotStatus(null), 4000);
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateAiHunt = async (customPrompt?: string, customTech?: string) => {
    setIsGeneratingAi(true);
    const p = customPrompt || aiPrompt;
    const t = customTech || selectedTech;
    try {
      const res = await fetch("/api/ai/hunt-hypotheses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: p, technique: t }),
      });
      const data: AIHuntingResponse = await res.json();
      setAiResult(data);
    } catch (err) {
      console.error("Error generating AI hunt:", err);
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const copyToClipboard = (text: string, sectionKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionKey);
    setTimeout(() => setCopiedSection(null), 2500);
  };

  const handleDeploySigma = () => {
    setDeployedStatus("Sigma Rule deployed to Active Detection Engine & SIEM Stream!");
    setTimeout(() => setDeployedStatus(null), 4000);
  };

  return (
    <div className="space-y-5">
      {/* AI Threat Hunting Header Card */}
      <div className="p-4 sm:p-5 rounded-lg bg-[#111821] border border-cyan-500/40 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-md bg-cyan-500/20 border border-cyan-500/40 text-cyan-300">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-[#e8edf2] flex items-center gap-2">
                Autonomous AI Threat Hunter & Rule Synthesizer
                <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  Gemini 3.7 Server-Side
                </span>
              </h2>
              <p className="text-xs text-[#94a3b8]">
                Generate threat hunting hypotheses, production Sigma YAML rules, YARA signatures, and automated SOAR playbooks from telemetry context
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleGenerateAiHunt()}
              disabled={isGeneratingAi}
              className="flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all disabled:opacity-50"
            >
              {isGeneratingAi ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin" />
                  Synthesizing Threat Models...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Execute Autonomous Hunt
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Technique Chips */}
        <div className="mb-3">
          <div className="text-[11px] text-[#94a3b8] mb-1.5 font-medium">Quick Technique Targets:</div>
          <div className="flex flex-wrap gap-2">
            {quickHuntTechniques.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  setSelectedTech(item.id);
                  setAiPrompt(item.prompt);
                  handleGenerateAiHunt(item.prompt, item.id);
                }}
                className={`px-2.5 py-1 rounded text-xs transition-all border ${
                  selectedTech === item.id
                    ? "bg-cyan-500/20 border-cyan-500 text-cyan-200"
                    : "bg-[#151e29] border-[#243244] text-[#94a3b8] hover:text-[#e8edf2] hover:bg-[#1a2636]"
                }`}
              >
                {item.name}
              </button>
            ))}
          </div>
        </div>

        {/* Custom Hunter Prompt */}
        <div className="relative">
          <textarea
            value={aiPrompt}
            onChange={(e) => setAiPrompt(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 text-xs bg-[#0b0f14] text-[#e8edf2] rounded border border-[#243244] focus:outline-none focus:border-cyan-500"
            placeholder="Describe an adversary behavior, suspicious telemetry pattern, or RF vector to hunt for..."
          />
        </div>
      </div>

      {deployedStatus && (
        <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{deployedStatus}</span>
        </div>
      )}

      {/* AI Synthesis Output */}
      {aiResult && (
        <div className="space-y-4">
          {/* Threat Intel & Hypothesis Banner */}
          <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300">
                <Shield className="w-4 h-4" />
                <span>Threat Hunting Hypothesis: {aiResult.hypothesis.title}</span>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#151e29] border border-[#243244] text-slate-300">
                Source: {aiResult.source}
              </span>
            </div>

            <p className="text-xs text-[#cbd5e1] leading-relaxed">
              {aiResult.threat_intel_summary}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-[#1e2a38] text-xs">
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244]">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Targeted Technique</div>
                <div className="font-semibold text-emerald-400">{aiResult.hypothesis.targeted_technique}</div>
              </div>
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244]">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Confidence Score</div>
                <div className="font-semibold text-cyan-400">
                  {Math.round(aiResult.hypothesis.confidence * 100)}% Match
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244]">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Required Telemetry</div>
                <div className="text-[#cbd5e1] truncate">{aiResult.hypothesis.data_sources_required.join(", ")}</div>
              </div>
            </div>

            <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244]">
              <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Detection Logic Query</div>
              <code className="text-xs font-mono text-cyan-300 break-all">{aiResult.hypothesis.detection_logic_query}</code>
            </div>
          </div>

          {/* Sigma Rule + YARA Rule + SOAR Playbook 3-Column Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Sigma Rule */}
            <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-[#e8edf2]">
                    <FileCode2 className="w-4 h-4 text-emerald-400" />
                    <span>Sigma Detection Rule</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(aiResult.sigma_rule.raw_yaml, "sigma")}
                    className="p-1 rounded bg-[#151e29] hover:bg-[#1e2a38] text-slate-300 text-xs flex items-center gap-1 border border-[#243244]"
                    title="Copy YAML"
                  >
                    {copiedSection === "sigma" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span className="text-[10px]">YAML</span>
                  </button>
                </div>
                <div className="text-xs font-medium text-slate-300 mb-1">{aiResult.sigma_rule.title}</div>
                <p className="text-[11px] text-[#94a3b8] mb-3">{aiResult.sigma_rule.description}</p>
                <div className="p-2 rounded bg-[#0b0f14] border border-[#243244] font-mono text-[10px] text-emerald-300 max-h-48 overflow-y-auto whitespace-pre">
                  {aiResult.sigma_rule.raw_yaml}
                </div>
              </div>

              <div className="pt-3 mt-3 border-t border-[#1e2a38] flex items-center justify-between">
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                  Level: {aiResult.sigma_rule.level}
                </span>
                <button
                  onClick={handleDeploySigma}
                  className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold transition-colors flex items-center gap-1"
                >
                  <Zap className="w-3 h-3" />
                  Deploy Rule
                </button>
              </div>
            </div>

            {/* YARA Rule */}
            <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-[#e8edf2]">
                    <Shield className="w-4 h-4 text-cyan-400" />
                    <span>YARA Memory / Disk Rule</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(aiResult.yara_rule.raw_yara, "yara")}
                    className="p-1 rounded bg-[#151e29] hover:bg-[#1e2a38] text-slate-300 text-xs flex items-center gap-1 border border-[#243244]"
                    title="Copy YARA"
                  >
                    {copiedSection === "yara" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span className="text-[10px]">YARA</span>
                  </button>
                </div>
                <div className="text-xs font-medium text-slate-300 mb-1">{aiResult.yara_rule.rule_name}</div>
                <p className="text-[11px] text-[#94a3b8] mb-3">{aiResult.yara_rule.description}</p>
                <div className="p-2 rounded bg-[#0b0f14] border border-[#243244] font-mono text-[10px] text-cyan-300 max-h-48 overflow-y-auto whitespace-pre">
                  {aiResult.yara_rule.raw_yara}
                </div>
              </div>

              <div className="pt-3 mt-3 border-t border-[#1e2a38] flex items-center justify-between">
                <span className="text-[10px] text-[#94a3b8]">Threat: {aiResult.yara_rule.threat_actor || "Universal"}</span>
                <button
                  onClick={() => copyToClipboard(aiResult.yara_rule.raw_yara, "yara")}
                  className="px-2.5 py-1 rounded bg-[#151e29] hover:bg-[#1e2a38] text-cyan-300 text-[11px] font-semibold transition-colors border border-[#243244]"
                >
                  Copy Rule
                </button>
              </div>
            </div>

            {/* SOAR Automated Playbook */}
            <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-[#e8edf2]">
                    <Workflow className="w-4 h-4 text-purple-400" />
                    <span>SOAR Response Playbook</span>
                  </div>
                  <span className="text-[10px] font-mono text-purple-300 px-1.5 py-0.5 rounded bg-purple-500/20 border border-purple-500/40">
                    {aiResult.playbook.playbook_id}
                  </span>
                </div>
                <div className="text-xs font-medium text-slate-300 mb-1">{aiResult.playbook.name}</div>
                <div className="space-y-1.5 mb-3">
                  {aiResult.playbook.steps.map((step) => (
                    <div
                      key={step.step_num}
                      className="p-1.5 rounded bg-[#0b0f14] border border-[#243244] flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="w-4 h-4 rounded-full bg-purple-500/20 text-purple-300 flex items-center justify-center font-mono text-[9px]">
                          {step.step_num}
                        </span>
                        <span className="text-[#e8edf2]">{step.action_type}</span>
                      </div>
                      <span className="text-[#94a3b8] font-mono text-[10px] truncate max-w-[100px]">{step.target}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-3 border-t border-[#1e2a38] flex items-center justify-between">
                <span className="text-[10px] text-[#94a3b8]">Technique: {aiResult.playbook.mitre_technique}</span>
                <button
                  onClick={() => copyToClipboard(aiResult.playbook.raw_yaml, "pb")}
                  className="px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white text-[11px] font-semibold transition-colors flex items-center gap-1"
                >
                  <Play className="w-3 h-3" />
                  Stage Playbook
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* KQL Query Console */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              KQL Advanced Hunting Console
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Query across raw security lake events, normalized streams, and behavioral detections
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-[#94a3b8] mr-1">Templates:</span>
            {sampleQueries.map((sq, i) => (
              <button
                key={i}
                onClick={() => setQuery(sq.kql)}
                className="px-2 py-0.5 rounded text-[11px] bg-[#151e29] hover:bg-[#1e2a38] text-cyan-300 border border-[#243244] transition-colors"
              >
                {sq.name}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-2.5">
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 text-xs font-mono bg-[#0b0f14] text-cyan-300 rounded border border-[#243244] focus:outline-none focus:border-cyan-500"
            placeholder="Enter KQL query syntax (e.g. alerts | where score >= 0.8 | take 50)..."
          />

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#94a3b8]">Limit:</span>
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="px-2 py-1 text-xs bg-[#151e29] text-[#e8edf2] rounded border border-[#243244] focus:outline-none"
              >
                <option value={20}>20 rows</option>
                <option value={50}>50 rows</option>
                <option value={100}>100 rows</option>
                <option value={200}>200 rows</option>
              </select>

              <button
                onClick={handleRunQuery}
                disabled={isRunning}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                {isRunning ? "Executing Query..." : "Run Query"}
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCreateSnapshot}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-slate-300 text-xs font-medium border border-[#243244] transition-colors"
                title="Create Lake Snapshot"
              >
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                Take Lake Snapshot
              </button>

              {queryResult && queryResult.rows.length > 0 && (
                <button
                  onClick={() => {
                    const headers = Object.keys(queryResult.rows[0]);
                    const csvRows = [
                      headers.join(","),
                      ...queryResult.rows.map((row) =>
                        headers.map((h) => JSON.stringify(row[h] ?? "")).join(",")
                      ),
                    ];
                    const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `hunt_results_${Date.now()}.csv`;
                    a.click();
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-emerald-400 text-xs font-medium border border-[#243244] transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export CSV
                </button>
              )}
            </div>
          </div>

          {lakeSnapshotStatus && (
            <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              <span>{lakeSnapshotStatus}</span>
            </div>
          )}
        </div>
      </div>

      {/* Query Results Table */}
      {queryResult && (
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#e8edf2]">Query Execution Results</span>
            <span className="text-xs text-[#94a3b8] font-mono">
              {queryResult.row_count} rows in {queryResult.elapsed_ms}ms
            </span>
          </div>

          {queryResult.rows.length === 0 ? (
            <div className="p-6 text-center text-xs text-[#94a3b8]">No records matched the query parameters.</div>
          ) : (
            <div className="overflow-x-auto max-h-96 border border-[#243244] rounded">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#151e29] text-[#94a3b8] font-mono sticky top-0">
                  <tr>
                    {Object.keys(queryResult.rows[0]).map((key) => (
                      <th key={key} className="p-2 border-b border-[#243244] whitespace-nowrap">
                        {key}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2a38] font-mono text-[11px]">
                  {queryResult.rows.map((row, idx) => (
                    <tr key={idx} className="hover:bg-[#151e29]/50 text-[#cbd5e1]">
                      {Object.keys(row).map((key) => (
                        <td key={key} className="p-2 whitespace-nowrap max-w-xs truncate">
                          {typeof row[key] === "object" ? JSON.stringify(row[key]) : String(row[key] ?? "")}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
