import React, { useState } from "react";
import { InvestigationReport, AttackTimelineEntry } from "../../types";
import { Shield, Layers, Clock, Terminal, Download, Users, FileCode, CheckCircle2, ChevronRight } from "lucide-react";

interface InvestigationTabProps {
  investigation: InvestigationReport | null;
}

const PHASE_LABELS: Record<number, string> = {
  1: "Phase 1 - Credential Access",
  2: "Phase 2 - Privilege Escalation",
  3: "Phase 3 - Lateral Movement",
  4: "Phase 4 - Command & Control",
  5: "Phase 5 - Collection",
  6: "Phase 6 - Exfiltration",
  7: "Phase 7 - Impact / Destruction",
};

export const InvestigationTab: React.FC<InvestigationTabProps> = ({ investigation }) => {
  const [selectedPhase, setSelectedPhase] = useState<number | "All">("All");
  const [selectedEvent, setSelectedEvent] = useState<AttackTimelineEntry | null>(null);

  if (!investigation) {
    return (
      <div className="p-8 text-center text-[#94a3b8] bg-[#111821] rounded-lg border border-[#243244]">
        Loading ATT&CK investigation intelligence...
      </div>
    );
  }

  const { summary, timeline } = investigation;
  const filteredTimeline = selectedPhase === "All"
    ? timeline
    : timeline.filter(t => t.phase === selectedPhase);

  const activeEvent = selectedEvent || filteredTimeline[0];

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(investigation, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attack_investigation_report.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Top Banner: MITRE ATT&CK Matrix Summary */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              MITRE ATT&CK Investigation Timeline & Kill-Chain
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Automated multi-stage kill chain reconstruction from ingested sensor signals and correlation clusters
            </p>
          </div>

          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export ATT&CK Report</span>
          </button>
        </div>

        {/* Phase Selectors Bar */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-[#243244]">
          <button
            onClick={() => setSelectedPhase("All")}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              selectedPhase === "All"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "bg-[#151e29] text-[#94a3b8] hover:text-[#e8edf2] border border-[#243244]"
            }`}
          >
            All Phases ({timeline.length})
          </button>
          {[1, 2, 3, 4, 5, 6, 7].map(phase => {
            const count = timeline.filter(t => t.phase === phase).length;
            return (
              <button
                key={phase}
                onClick={() => setSelectedPhase(phase)}
                className={`px-2.5 py-1 text-xs rounded transition-colors flex items-center gap-1.5 ${
                  selectedPhase === phase
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                    : "bg-[#151e29] text-[#94a3b8] hover:text-[#e8edf2] border border-[#243244]"
                }`}
              >
                <span>{PHASE_LABELS[phase]}</span>
                {count > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-cyan-900/60 text-cyan-200 text-[10px]">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Grid: Kill-Chain Timeline Stream + Evidence Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Sequential Timeline Events */}
        <div className="lg:col-span-7 p-4 rounded-lg bg-[#111821] border border-[#243244] max-h-[600px] overflow-y-auto">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3">
            Correlated Attack Sequence ({filteredTimeline.length} events)
          </h4>

          {filteredTimeline.length === 0 ? (
            <div className="p-6 text-center text-xs text-[#94a3b8]">
              No events identified for this phase in the current telemetry batch.
            </div>
          ) : (
            <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#243244]">
              {filteredTimeline.map((item, idx) => {
                const isSelected = activeEvent?.event_id === item.event_id;
                const phaseColor =
                  item.phase >= 6 ? "bg-rose-500" : item.phase >= 4 ? "bg-amber-400" : "bg-cyan-400";

                return (
                  <div
                    key={idx}
                    onClick={() => setSelectedEvent(item)}
                    className={`relative p-3 rounded-lg border transition-all cursor-pointer ${
                      isSelected
                        ? "bg-cyan-950/30 border-cyan-500/50 shadow-sm"
                        : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
                    }`}
                  >
                    {/* Circle marker */}
                    <div
                      className={`absolute -left-[19px] top-3.5 w-2.5 h-2.5 rounded-full ring-4 ring-[#111821] ${phaseColor}`}
                    />

                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-[11px] text-[#94a3b8]">
                        {(item.timestamp || "").replace("T", " ").substring(0, 19)}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-[#0b0f14] text-cyan-300 border border-[#243244]">
                        {item.technique_id} - {item.tactic}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-[#e8edf2] mb-1">
                      {item.technique}
                    </div>

                    <div className="text-xs text-[#94a3b8] line-clamp-2 mb-2 font-mono">
                      {item.evidence}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-[#64748b]">
                      {item.source_ip && <span>Src: <b className="text-[#94a3b8] font-mono">{item.source_ip}</b></span>}
                      {item.destination_ip && <span>Dst: <b className="text-[#94a3b8] font-mono">{item.destination_ip}</b></span>}
                      {item.username && <span>User: <b className="text-[#94a3b8]">{item.username}</b></span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Detailed Technique & Forensic Artifact Inspector */}
        <div className="lg:col-span-5 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3">
            Technique Evidence & Entity Pivot
          </h4>

          {activeEvent ? (
            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-[#151e29] border border-[#243244] space-y-2">
                <div>
                  <span className="text-[#94a3b8] block text-[11px]">MITRE Classification:</span>
                  <div className="font-semibold text-sm text-cyan-300">
                    {activeEvent.technique_id}: {activeEvent.technique}
                  </div>
                  <span className="text-xs text-[#94a3b8]">{activeEvent.tactic} ({PHASE_LABELS[activeEvent.phase]})</span>
                </div>

                <div className="pt-2 border-t border-[#243244]/60 grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-[#94a3b8] block text-[10px]">Source Node:</span>
                    <span className="font-mono text-[#e8edf2] font-semibold">{activeEvent.source_ip || "Unknown"}</span>
                  </div>
                  <div>
                    <span className="text-[#94a3b8] block text-[10px]">Destination / C2:</span>
                    <span className="font-mono text-[#e8edf2] font-semibold">{activeEvent.destination_ip || "Internal"}</span>
                  </div>
                  <div>
                    <span className="text-[#94a3b8] block text-[10px]">Actor Account:</span>
                    <span className="font-mono text-[#e8edf2]">{activeEvent.username || "System/Admin"}</span>
                  </div>
                  <div>
                    <span className="text-[#94a3b8] block text-[10px]">Risk Severity:</span>
                    <span className="font-semibold text-rose-400">{activeEvent.level} ({((activeEvent.score || 0.8) * 100).toFixed(0)}%)</span>
                  </div>
                </div>
              </div>

              <div>
                <span className="text-[#94a3b8] block mb-1 font-semibold">Forensic Evidence Description:</span>
                <div className="p-2.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] font-mono text-[11px]">
                  {activeEvent.evidence}
                </div>
              </div>

              {/* Entity Pivot Chips */}
              <div>
                <span className="text-[#94a3b8] block mb-1 font-semibold">Correlated Graph Entities:</span>
                <div className="flex flex-wrap gap-1.5">
                  {summary.entities.slice(0, 8).map((entity, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded text-[11px] bg-[#151e29] border border-[#243244] font-mono text-cyan-300"
                    >
                      {entity}
                    </span>
                  ))}
                </div>
              </div>

              {/* Tactics breakdown list */}
              <div>
                <span className="text-[#94a3b8] block mb-1 font-semibold">Tactics Volume Summary:</span>
                <div className="space-y-1">
                  {Object.entries(summary.tactics).map(([tactic, count], idx) => (
                    <div key={idx} className="flex justify-between items-center text-[11px] py-1 border-b border-[#1e2a38]">
                      <span className="text-[#94a3b8]">{tactic}</span>
                      <span className="font-mono font-bold text-cyan-400">{count} events</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-[#94a3b8]">
              Select an event from the sequence to view technical evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
