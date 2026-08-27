import React from "react";
import { Sliders, Filter, Upload, Zap, Database, RefreshCw, Layers } from "lucide-react";

interface SidebarProps {
  riskFloor: number;
  onRiskFloorChange: (val: number) => void;
  selectedLevels: string[];
  onToggleLevel: (lvl: string) => void;
  onGenerateDemo: () => void;
  isGenerating: boolean;
  onUploadTelemetry: (e: React.ChangeEvent<HTMLInputElement>) => void;
  alertsCount: number;
  totalLoadedEvents: number;
}

const ALL_LEVELS = ["Critical", "High", "Medium", "Low", "Info"];

export const Sidebar: React.FC<SidebarProps> = ({
  riskFloor,
  onRiskFloorChange,
  selectedLevels,
  onToggleLevel,
  onGenerateDemo,
  isGenerating,
  onUploadTelemetry,
  alertsCount,
  totalLoadedEvents,
}) => {
  return (
    <aside className="w-full lg:w-64 flex-shrink-0 space-y-4">
      {/* Telemetry Source Card */}
      <div className="p-3.5 rounded-lg bg-[#111821] border border-[#243244] text-xs space-y-3">
        <div className="flex items-center gap-2 font-semibold text-[#e8edf2]">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Active Telemetry Feed</span>
        </div>

        <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60 space-y-1">
          <div className="text-[11px] text-[#94a3b8]">Live Stream:</div>
          <div className="font-mono text-cyan-300 font-bold truncate">data/outputs/alerts.jsonl</div>
          <div className="text-[10px] text-[#94a3b8]">
            {totalLoadedEvents} events normalized & analyzed
          </div>
        </div>

        {/* Risk Score Floor Slider */}
        <div className="space-y-1.5 pt-1">
          <div className="flex justify-between items-center text-[11px]">
            <span className="text-[#94a3b8] flex items-center gap-1">
              <Sliders className="w-3 h-3 text-cyan-400" /> Risk Floor
            </span>
            <span className="font-mono text-cyan-300 font-bold">{(riskFloor * 100).toFixed(0)}%</span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={riskFloor}
            onChange={e => onRiskFloorChange(parseFloat(e.target.value))}
            className="w-full h-1.5 bg-[#151e29] rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
        </div>

        {/* Severity Checkboxes */}
        <div className="space-y-1.5 pt-1">
          <span className="text-[11px] text-[#94a3b8] flex items-center gap-1 mb-1">
            <Filter className="w-3 h-3 text-cyan-400" /> Severity Filter
          </span>
          <div className="grid grid-cols-2 gap-1.5">
            {ALL_LEVELS.map(lvl => {
              const isChecked = selectedLevels.includes(lvl);
              return (
                <button
                  key={lvl}
                  onClick={() => onToggleLevel(lvl)}
                  className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors text-left flex items-center justify-between ${
                    isChecked
                      ? "bg-cyan-950/60 text-cyan-300 border-cyan-700/60"
                      : "bg-[#151e29] text-[#64748b] border-[#243244]"
                  }`}
                >
                  <span>{lvl}</span>
                  {isChecked && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sensor Ingest & Demo Generator Card */}
      <div className="p-3.5 rounded-lg bg-[#111821] border border-[#243244] text-xs space-y-3">
        <div className="font-semibold text-[#e8edf2] flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          <span>Ingest Operations</span>
        </div>

        <div>
          <label className="block text-[11px] text-[#94a3b8] mb-1">Import Telemetry JSON:</label>
          <label className="flex items-center justify-center gap-1.5 w-full py-2 rounded bg-[#151e29] hover:bg-[#1e2a38] border border-dashed border-[#243244] text-[#e8edf2] cursor-pointer text-[11px] transition-colors">
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Select JSON File</span>
            <input type="file" accept=".json" onChange={onUploadTelemetry} className="hidden" />
          </label>
        </div>

        <div className="pt-2 border-t border-[#243244]/60">
          <button
            onClick={onGenerateDemo}
            disabled={isGenerating}
            className="w-full py-2 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 font-medium text-xs flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? "animate-spin" : ""}`} />
            <span>{isGenerating ? "Simulating..." : "Generate Attack Scenario"}</span>
          </button>
          <span className="text-[10px] text-[#64748b] block text-center mt-1">
            Simulates ransomware, C2 beaconing & credential stuffing
          </span>
        </div>
      </div>
    </aside>
  );
};
