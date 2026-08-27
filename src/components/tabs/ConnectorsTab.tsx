import React from "react";
import { ConnectorItem } from "../../types";
import { Network, CheckCircle2, AlertCircle, HelpCircle, HardDrive, ListOrdered } from "lucide-react";

interface ConnectorsTabProps {
  connectors: ConnectorItem[];
  summary: { implemented: number; demo_blueprints: number; total_connectors: number };
  setupPlan: Array<{ step: number; action: string; status: string }>;
}

export const ConnectorsTab: React.FC<ConnectorsTabProps> = ({
  connectors,
  summary,
  setupPlan,
}) => {
  return (
    <div className="space-y-4">
      {/* Connectors Catalog */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Live Telemetry Connector Catalog
            </h3>
            <p className="text-xs text-[#94a3b8]">
              {summary.implemented} active telemetry parsers | {summary.demo_blueprints} cloud blueprints | {summary.total_connectors} total supported feeds
            </p>
          </div>
        </div>

        <div className="overflow-x-auto border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244]">
              <tr>
                <th className="py-2.5 px-3">Connector Name</th>
                <th className="py-2.5 px-3">Telemetry Class</th>
                <th className="py-2.5 px-3">Data Format</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
              {connectors.map((c, idx) => (
                <tr key={idx} className="hover:bg-[#151e29]/50">
                  <td className="py-2.5 px-3 font-semibold text-cyan-300">{c.name}</td>
                  <td className="py-2.5 px-3 text-[#94a3b8]">{c.type}</td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-[#e8edf2]">{c.format}</td>
                  <td className="py-2.5 px-3 text-[#94a3b8] max-w-sm truncate">{c.description}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        c.status === "Active"
                          ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                          : c.status === "Ready"
                          ? "bg-cyan-950 text-cyan-300 border-cyan-800"
                          : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
                      }`}
                    >
                      {c.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Setup Action Plan */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
          <ListOrdered className="w-3.5 h-3.5 text-cyan-400" />
          Sensor Onboarding Action Plan
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          {setupPlan.map((step, idx) => (
            <div key={idx} className="p-3 rounded bg-[#151e29] border border-[#243244]">
              <div className="flex justify-between items-center mb-1.5">
                <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 flex items-center justify-center font-mono text-[10px] font-bold">
                  {step.step}
                </span>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {step.status}
                </span>
              </div>
              <div className="font-medium text-[#e8edf2]">{step.action}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
