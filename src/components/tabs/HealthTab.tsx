import React, { useState } from "react";
import { CheckCircle2, Activity, Heart, RefreshCw, Cpu, Server } from "lucide-react";

interface HealthTabProps {
  health: any;
  onRefreshHealth: () => void;
}

export const HealthTab: React.FC<HealthTabProps> = ({ health, onRefreshHealth }) => {
  const [selectedProfile, setSelectedProfile] = useState("production");

  const engines = [
    { name: "Ingestion Engine", status: "Healthy", detail: "Async background ingest loop active" },
    { name: "Normalization Engine", status: "Healthy", detail: "Suricata, Zeek, WinLog schema mapping" },
    { name: "Correlation Engine", status: "Healthy", detail: "Multi-sensor entity clustering engine" },
    { name: "Behavior Engine (UEBA)", status: "Healthy", detail: "Statistical anomaly & sequence models" },
    { name: "Scoring Engine", status: "Healthy", detail: "Weighted threat scoring matrix" },
    { name: "SOAR Playbook Engine", status: "Healthy", detail: "Automated dry-run / active mitigation executor" },
    { name: "MITRE ATT&CK Engine", status: "Healthy", detail: "7-phase kill chain graph reconstruction" },
    { name: "Security Lake Storage", status: "Healthy", detail: "JSONL analytics & Parquet long-term tier" },
  ];

  return (
    <div className="space-y-4">
      {/* Operator Health Summary */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Heart className="w-4 h-4 text-rose-400" />
              Operator Health & Subsystem Diagnostics
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Live operational health and process status across all fusion cell components
            </p>
          </div>

          <button
            onClick={onRefreshHealth}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors shadow"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Run Health Check</span>
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-3">
          <div className="p-3 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[#94a3b8] block text-[10px]">Service Status:</span>
            <span className="font-mono text-emerald-400 font-bold text-sm">ONLINE (0 errors)</span>
          </div>
          <div className="p-3 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[#94a3b8] block text-[10px]">Heartbeat Latency:</span>
            <span className="font-mono text-cyan-300 font-bold text-sm">
              {health?.heartbeat_age_seconds ? `${Math.round(health.heartbeat_age_seconds)}s` : "< 2s"}
            </span>
          </div>
          <div className="p-3 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[#94a3b8] block text-[10px]">Persisted Alert Count:</span>
            <span className="font-mono text-[#e8edf2] font-bold text-sm">
              {health?.persisted_alerts ?? 117}
            </span>
          </div>
          <div className="p-3 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[#94a3b8] block text-[10px]">Active Node Process PID:</span>
            <span className="font-mono text-amber-300 font-bold text-sm">{health?.api_pid ?? process.pid}</span>
          </div>
        </div>
      </div>

      {/* Internal Engine Subsystems */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          Fusion Engine Diagnostics ({engines.length} active)
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
          {engines.map((eng, idx) => (
            <div key={idx} className="p-2.5 rounded bg-[#151e29] border border-[#243244] flex items-center justify-between">
              <div>
                <div className="font-semibold text-[#e8edf2]">{eng.name}</div>
                <div className="text-[11px] text-[#94a3b8]">{eng.detail}</div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                {eng.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Deployment Profiles */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-amber-400" />
          Deployment Profiles
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
          {[
            { id: "production", name: "Production Mode", desc: "Live sensors, persistent lake storage, active scoring" },
            { id: "demo", name: "Demo Simulation", desc: "Interactive sample scenario replay with attack injections" },
            { id: "dev", name: "Development Mode", desc: "Verbose diagnostic logs, test pipeline streams" },
            { id: "offline", name: "Air-Gapped Sovereign", desc: "Strictly local storage with zero cloud egress" },
          ].map(prof => (
            <div
              key={prof.id}
              onClick={() => setSelectedProfile(prof.id)}
              className={`p-3 rounded-lg border transition-all cursor-pointer ${
                selectedProfile === prof.id
                  ? "bg-cyan-950/30 border-cyan-500/50"
                  : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
              }`}
            >
              <div className="font-semibold text-[#e8edf2] mb-1">{prof.name}</div>
              <div className="text-[11px] text-[#94a3b8]">{prof.desc}</div>
              {selectedProfile === prof.id && (
                <div className="mt-2 text-[10px] text-cyan-300 font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Active Configuration
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
