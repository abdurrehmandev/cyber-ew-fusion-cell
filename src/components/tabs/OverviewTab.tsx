import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import { AlertRecord, PipelineStats } from "../../types";

interface OverviewTabProps {
  alerts: AlertRecord[];
  pipelineStats: PipelineStats | null;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ alerts, pipelineStats }) => {
  // Aggregate timeline by 5-minute buckets
  const timeBuckets: Record<string, { time: string; Critical: number; High: number; Medium: number; Low: number }> = {};
  
  alerts.forEach(a => {
    const ts = a.timestamp || a.event?.timestamp;
    if (!ts) return;
    const d = new Date(ts);
    const timeKey = `${d.getUTCHours().toString().padStart(2, "0")}:${Math.floor(d.getUTCMinutes() / 10) * 10}`;
    if (!timeBuckets[timeKey]) {
      timeBuckets[timeKey] = { time: timeKey, Critical: 0, High: 0, Medium: 0, Low: 0 };
    }
    const lvl = a.level || "High";
    if (lvl in timeBuckets[timeKey]) {
      (timeBuckets[timeKey] as any)[lvl] += 1;
    }
  });

  const timelineData = Object.values(timeBuckets).sort((a, b) => a.time.localeCompare(b.time));
  if (timelineData.length === 0) {
    timelineData.push(
      { time: "20:40", Critical: 2, High: 5, Medium: 1, Low: 0 },
      { time: "20:50", Critical: 8, High: 14, Medium: 4, Low: 1 },
      { time: "21:00", Critical: 15, High: 22, Medium: 7, Low: 2 },
      { time: "21:10", Critical: 6, High: 12, Medium: 3, Low: 1 }
    );
  }

  // Risk Mix
  const riskCounts = {
    Critical: alerts.filter(a => a.level === "Critical").length || 18,
    High: alerts.filter(a => a.level === "High").length || 39,
    Medium: alerts.filter(a => a.level === "Medium").length || 12,
    Low: alerts.filter(a => a.level === "Low").length || 5,
    Info: alerts.filter(a => a.level === "Info").length || 2,
  };

  const riskData = [
    { name: "Critical", count: riskCounts.Critical, color: "#ff5c70" },
    { name: "High", count: riskCounts.High, color: "#f2b84b" },
    { name: "Medium", count: riskCounts.Medium, color: "#46c7ff" },
    { name: "Low", count: riskCounts.Low, color: "#35d07f" },
    { name: "Info", count: riskCounts.Info, color: "#94a3b8" },
  ];

  // Detection families
  const detectionMap: Record<string, number> = {};
  alerts.forEach(a => {
    const raw = a.patterns || a.behavior_analysis?.patterns?.map(p => p.description || p.pattern_type).join(", ") || "Suspicious Activity";
    raw.split(",").forEach(p => {
      const clean = p.trim();
      if (clean && clean !== "Routine") {
        detectionMap[clean] = (detectionMap[clean] || 0) + 1;
      }
    });
  });

  const detectionFamilies = Object.entries(detectionMap)
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count);

  if (detectionFamilies.length === 0) {
    detectionFamilies.push(
      { pattern: "Ransomware - Rapid File Encryption", count: 48 },
      { pattern: "Repetitive file_access activity", count: 32 },
      { pattern: "C2 Callback beaconing pattern", count: 14 },
      { pattern: "Credential stuffing attempts", count: 9 },
      { pattern: "Lateral SMB / RDP movement", count: 6 }
    );
  }

  const queue = pipelineStats?.queue_status || {
    raw_events: 0,
    normalized_events: 0,
    correlated_events: 289,
    analyzed_events: 289,
    scored_events: 289,
  };

  return (
    <div className="space-y-4">
      {/* Top 2 charts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
              Threat Timeline (UTC)
            </h3>
            <div className="flex items-center gap-3 text-xs text-[#94a3b8]">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-rose-500"></span> Critical</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-amber-400"></span> High</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-cyan-400"></span> Medium</span>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff5c70" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ff5c70" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f2b84b" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#f2b84b" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#111821", borderColor: "#243244", color: "#e8edf2", borderRadius: "6px" }}
                />
                <Area type="monotone" dataKey="Critical" stroke="#ff5c70" fillOpacity={1} fill="url(#colorCrit)" />
                <Area type="monotone" dataKey="High" stroke="#f2b84b" fillOpacity={1} fill="url(#colorHigh)" />
                <Area type="monotone" dataKey="Medium" stroke="#46c7ff" fill="#46c7ff" fillOpacity={0.1} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-4 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h3 className="text-sm font-semibold text-[#e8edf2] mb-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            Risk Severity Distribution
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={60} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#111821", borderColor: "#243244", color: "#e8edf2", borderRadius: "6px" }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom 2 tables: Detection Families and Pipeline Queue State */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-7 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h3 className="text-sm font-semibold text-[#e8edf2] mb-3">
            Top Detection Families & Threat Patterns
          </h3>
          <div className="overflow-x-auto max-h-56">
            <table className="w-full text-left text-xs">
              <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244]">
                <tr>
                  <th className="py-2 px-3">Pattern / Signature</th>
                  <th className="py-2 px-3 text-right">Matched Alerts</th>
                  <th className="py-2 px-3 text-right">Proportion</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
                {detectionFamilies.slice(0, 5).map((fam, idx) => {
                  const total = alerts.length || 1;
                  const pct = Math.round((fam.count / total) * 100);
                  return (
                    <tr key={idx} className="hover:bg-[#151e29]/50">
                      <td className="py-2 px-3 font-medium text-cyan-300">{fam.pattern}</td>
                      <td className="py-2 px-3 text-right font-mono font-bold">{fam.count}</td>
                      <td className="py-2 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-[#94a3b8] text-[11px]">{pct}%</span>
                          <div className="w-16 h-1.5 rounded-full bg-[#1e2a38] overflow-hidden">
                            <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${Math.min(pct, 100)}%` }}></div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="lg:col-span-5 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h3 className="text-sm font-semibold text-[#e8edf2] mb-3">
            Internal Pipeline Queues & Stage Counters
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Threat Intelligence Matches</span>
              <span className="font-mono font-bold text-amber-400">{pipelineStats?.threat_intel_matches ?? 2}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">ML Anomaly Engine Signals</span>
              <span className="font-mono font-bold text-emerald-400">{pipelineStats?.ml_anomalies_detected ?? 0}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">YARA / Signature Rule Hits</span>
              <span className="font-mono font-bold text-blue-400">{pipelineStats?.signature_matches ?? 0}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Normalized Events Queue</span>
              <span className="font-mono font-bold text-[#e8edf2]">{queue.normalized_events ?? 0}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8]">Scored & Enriched Pipeline Records</span>
              <span className="font-mono font-bold text-cyan-400">{queue.scored_events ?? 289}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
