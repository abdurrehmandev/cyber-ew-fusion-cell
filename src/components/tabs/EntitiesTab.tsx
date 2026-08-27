import React from "react";
import { AlertRecord } from "../../types";
import { Users, Server, Globe, Shield } from "lucide-react";

interface EntitiesTabProps {
  alerts: AlertRecord[];
}

export const EntitiesTab: React.FC<EntitiesTabProps> = ({ alerts }) => {
  // Aggregate Top Sources, Destinations, Users
  const srcMap: Record<string, { count: number; maxScore: number; levels: string[] }> = {};
  const dstMap: Record<string, { count: number; maxScore: number }> = {};
  const userMap: Record<string, { count: number; maxScore: number }> = {};

  alerts.forEach(a => {
    const sIp = a.event?.source_ip || a.source_ip;
    const dIp = a.event?.destination_ip || a.destination_ip;
    const user = a.event?.username || a.username;
    const score = a.score || 0.5;
    const lvl = a.level || "High";

    if (sIp) {
      if (!srcMap[sIp]) srcMap[sIp] = { count: 0, maxScore: 0, levels: [] };
      srcMap[sIp].count += 1;
      srcMap[sIp].maxScore = Math.max(srcMap[sIp].maxScore, score);
      if (!srcMap[sIp].levels.includes(lvl)) srcMap[sIp].levels.push(lvl);
    }
    if (dIp) {
      if (!dstMap[dIp]) dstMap[dIp] = { count: 0, maxScore: 0 };
      dstMap[dIp].count += 1;
      dstMap[dIp].maxScore = Math.max(dstMap[dIp].maxScore, score);
    }
    if (user) {
      if (!userMap[user]) userMap[user] = { count: 0, maxScore: 0 };
      userMap[user].count += 1;
      userMap[user].maxScore = Math.max(userMap[user].maxScore, score);
    }
  });

  const topSources = Object.entries(srcMap)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.count - a.count);

  const topDests = Object.entries(dstMap)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.count - a.count);

  const topUsers = Object.entries(userMap)
    .map(([username, data]) => ({ username, ...data }))
    .sort((a, b) => b.count - a.count);

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h3 className="text-sm font-semibold text-[#e8edf2] mb-1 flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" />
          Entity Analytics & Cross-Sensor Graph Pivots
        </h3>
        <p className="text-xs text-[#94a3b8]">
          Aggregated host, network destination, and user account risk profiles across telemetry streams
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Top Source Hosts */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-rose-400" />
            Top Originating Hosts ({topSources.length})
          </h4>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {topSources.map((src, i) => (
              <div key={i} className="p-2.5 rounded bg-[#151e29] border border-[#243244] text-xs">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-mono font-bold text-cyan-300">{src.ip}</span>
                  <span className="font-mono text-rose-400 font-semibold">{src.count} alerts</span>
                </div>
                <div className="flex justify-between text-[11px] text-[#94a3b8]">
                  <span>Peak Risk: {(src.maxScore * 100).toFixed(0)}%</span>
                  <span>Levels: {src.levels.join(", ")}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Target / C2 Destinations */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-amber-400" />
            Target & Callback Destinations ({topDests.length})
          </h4>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {topDests.map((dst, i) => (
              <div key={i} className="p-2.5 rounded bg-[#151e29] border border-[#243244] text-xs">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-mono font-bold text-[#e8edf2]">{dst.ip}</span>
                  <span className="font-mono text-amber-400 font-semibold">{dst.count} events</span>
                </div>
                <div className="text-[11px] text-[#94a3b8]">
                  Max Risk Score: {(dst.maxScore * 100).toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Impacted User Accounts */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            Impacted User Accounts ({topUsers.length})
          </h4>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {topUsers.map((u, i) => (
              <div key={i} className="p-2.5 rounded bg-[#151e29] border border-[#243244] text-xs">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-mono font-bold text-[#e8edf2]">{u.username}</span>
                  <span className="font-mono text-cyan-400 font-semibold">{u.count} signals</span>
                </div>
                <div className="text-[11px] text-[#94a3b8]">
                  Max Risk Score: {(u.maxScore * 100).toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
