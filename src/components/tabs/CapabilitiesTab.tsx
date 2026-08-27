import React from "react";
import { CapabilityItem } from "../../types";
import { CheckCircle2, Shield, Lock, Award, Zap } from "lucide-react";

interface CapabilitiesTabProps {
  capabilities: CapabilityItem[];
  runtimeMode: {
    label: string;
    operation_mode: string;
    mock_telemetry: boolean;
    windows_events: boolean;
    packet_events: boolean;
  } | null;
}

export const CapabilitiesTab: React.FC<CapabilitiesTabProps> = ({
  capabilities,
  runtimeMode,
}) => {
  return (
    <div className="space-y-4">
      {/* Capability Matrix */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Award className="w-4 h-4 text-cyan-400" />
              Sentinel-Class SIEM & Fusion Capability Matrix
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Comparison between standard enterprise SIEM benchmarks and local air-gapped cyber intelligence capabilities
            </p>
          </div>
          <span className="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
            {runtimeMode?.label || "Air-Gapped Local SOC"}
          </span>
        </div>

        <div className="overflow-x-auto border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244]">
              <tr>
                <th className="py-2.5 px-3">SIEM Capability</th>
                <th className="py-2.5 px-3">Enterprise Cloud Benchmark</th>
                <th className="py-2.5 px-3">Local Air-Gapped Implementation</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
              {capabilities.map((cap, idx) => (
                <tr key={idx} className="hover:bg-[#151e29]/50">
                  <td className="py-2.5 px-3 font-semibold text-cyan-300">{cap.capability}</td>
                  <td className="py-2.5 px-3 text-[#94a3b8]">{cap.benchmark}</td>
                  <td className="py-2.5 px-3 font-medium text-[#e8edf2]">{cap.local}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        cap.status === "Active"
                          ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                          : "bg-amber-950 text-amber-300 border-amber-800"
                      }`}
                    >
                      {cap.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Runtime Truth & Differentiators */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            Runtime Operational Posture
          </h4>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Mode Label</span>
              <span className="font-semibold text-cyan-300">{runtimeMode?.label || "Air-Gapped SOC"}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Deployment Mode</span>
              <span className="font-mono text-emerald-400 font-bold">{runtimeMode?.operation_mode || "production"}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Synthetic / Mock Telemetry</span>
              <span className="font-mono text-[#e8edf2]">{runtimeMode?.mock_telemetry ? "Enabled" : "Disabled (Live)"}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Windows Event Log Channel</span>
              <span className="font-mono text-emerald-400">Available</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Npcap Packet Capture</span>
              <span className="font-mono text-emerald-400">Available</span>
            </div>
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            Air-Gapped Architectural Benefits
          </h4>
          <div className="space-y-2 text-xs">
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60">
              <div className="font-semibold text-[#e8edf2] mb-0.5">Air-Gapped Sovereign Operation</div>
              <div className="text-[11px] text-[#94a3b8]">Local storage, local API engine, and offline dashboard with zero external telemetry leakage.</div>
            </div>
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60">
              <div className="font-semibold text-[#e8edf2] mb-0.5">Predictable Cost Control</div>
              <div className="text-[11px] text-[#94a3b8]">Zero per-gigabyte cloud ingestion bills or per-query pricing tiers.</div>
            </div>
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60">
              <div className="font-semibold text-[#e8edf2] mb-0.5">Built-in SOC Workflow</div>
              <div className="text-[11px] text-[#94a3b8]">Cases, IOC watchlists, automated SOAR playbooks, and MITRE ATT&CK timeline built directly into the core engine.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
