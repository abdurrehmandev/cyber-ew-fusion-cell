import React from "react";
import { AlertRecord } from "../../types";
import { ShieldCheck, Activity, UserCheck, HardDrive } from "lucide-react";

interface ProfilesTabProps {
  alerts: AlertRecord[];
}

export const ProfilesTab: React.FC<ProfilesTabProps> = ({ alerts }) => {
  const sampleProfiles = [
    {
      entity: "192.168.1.55 (Workstation-Fin01)",
      type: "Endpoint Host",
      anomaly_score: 0.88,
      baseline_events: 1420,
      anomalous_bursts: 4,
      patterns: "Rapid file rename/encrypt, abnormal outbound volume",
      status: "High Deviation",
    },
    {
      entity: "192.168.1.20 (AppServer-DC02)",
      type: "Server Host",
      anomaly_score: 0.76,
      baseline_events: 5280,
      anomalous_bursts: 2,
      patterns: "C2 beacon callback to 198.51.100.23:443",
      status: "Elevated Risk",
    },
    {
      entity: "admin_svc (Service Account)",
      type: "User Principal",
      anomaly_score: 0.82,
      baseline_events: 890,
      anomalous_bursts: 3,
      patterns: "Interactive logon at 02:14 AM outside business hours",
      status: "High Deviation",
    },
    {
      entity: "operator (Local Analyst)",
      type: "User Principal",
      anomaly_score: 0.12,
      baseline_events: 340,
      anomalous_bursts: 0,
      patterns: "Routine SOC queries and console management",
      status: "Normal Baseline",
    },
  ];

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h3 className="text-sm font-semibold text-[#e8edf2] mb-1 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          Behavioral Baseline Profiles & Anomaly Tracking (UEBA)
        </h3>
        <p className="text-xs text-[#94a3b8]">
          Continuous statistical and machine-learning deviation scoring for endpoint hosts and user identities
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sampleProfiles.map((prof, i) => (
          <div key={i} className="p-4 rounded-lg bg-[#111821] border border-[#243244] text-xs space-y-2.5">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-sm text-[#e8edf2] font-mono">{prof.entity}</span>
                <span className="text-[11px] text-[#94a3b8] block">{prof.type}</span>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                  prof.anomaly_score > 0.7
                    ? "bg-rose-950 text-rose-300 border-rose-800"
                    : "bg-emerald-950 text-emerald-300 border-emerald-800"
                }`}
              >
                {prof.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#243244]/60">
              <div>
                <span className="text-[#94a3b8] text-[10px]">Anomaly Score:</span>
                <div className="font-mono text-base font-bold text-amber-400">
                  {(prof.anomaly_score * 100).toFixed(0)}%
                </div>
              </div>
              <div>
                <span className="text-[#94a3b8] text-[10px]">Baseline Volume:</span>
                <div className="font-mono text-[#e8edf2] font-semibold">{prof.baseline_events} events</div>
              </div>
            </div>

            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60">
              <span className="text-[#94a3b8] block text-[10px]">Observed Behavioral Deviation:</span>
              <span className="font-mono text-cyan-300 text-[11px]">{prof.patterns}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
