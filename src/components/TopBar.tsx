import React from "react";
import { Shield, RefreshCw, Activity, Terminal, Download, Cpu, HardDrive } from "lucide-react";

interface TopBarProps {
  healthStatus: {
    status: string;
    live_service: boolean;
    heartbeat_age_seconds: number;
    persisted_alerts: number;
  } | null;
  onRefresh: () => void;
  isRefreshing: boolean;
  onExportBundle: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  healthStatus,
  onRefresh,
  isRefreshing,
  onExportBundle,
}) => {
  const isHealthy = healthStatus?.status === "ok";

  return (
    <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 mb-4 rounded-lg bg-[#111821]/95 border border-[#243244] shadow-md backdrop-blur-sm">
      <div className="flex items-center gap-3.5">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#e8edf2] font-sans">
              Cyber-EW Fusion Cell
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
              v1.1.0 SOC
            </span>
          </div>
          <p className="text-xs text-[#94a3b8] mt-0.5">
            Defensive cyber intelligence fusion, correlation engine & alert triage
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#151e29] border border-[#243244] text-xs">
          <span className={`w-2 h-2 rounded-full ${isHealthy ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
          <span className="font-semibold text-[#e8edf2]">
            {isHealthy ? "Live Engine" : "Local Standby"}
          </span>
          <span className="text-[#94a3b8] border-l border-[#243244] pl-2">
            {healthStatus?.heartbeat_age_seconds ? `${Math.round(healthStatus.heartbeat_age_seconds)}s ago` : "Online"}
          </span>
        </div>

        <button
          onClick={onExportBundle}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-[#151e29] hover:bg-[#1e2a38] text-cyan-300 border border-[#243244] transition-colors"
          title="Export SOC Investigation Bundle"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Bundle</span>
        </button>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
};
