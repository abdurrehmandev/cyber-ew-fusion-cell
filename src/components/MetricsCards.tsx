import React from "react";
import { Activity, AlertTriangle, Crosshair, Users, Briefcase, Database } from "lucide-react";

interface MetricsCardsProps {
  eventsCount: number;
  alertsCount: number;
  criticalCount: number;
  highCount: number;
  detectionsCount: number;
  entitiesCount: number;
  openCasesCount: number;
  totalCasesCount: number;
  iocsCount: number;
  pipelineProcessed: number;
}

export const MetricsCards: React.FC<MetricsCardsProps> = ({
  eventsCount,
  alertsCount,
  criticalCount,
  highCount,
  detectionsCount,
  entitiesCount,
  openCasesCount,
  totalCasesCount,
  iocsCount,
  pipelineProcessed,
}) => {
  const cards = [
    {
      title: "Events",
      value: eventsCount.toLocaleString(),
      subtitle: `${pipelineProcessed.toLocaleString()} processed by pipeline`,
      icon: Activity,
      color: "text-blue-400",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-500/20",
    },
    {
      title: "Alerts",
      value: alertsCount.toLocaleString(),
      subtitle: `${criticalCount} critical / ${highCount} high risk`,
      icon: AlertTriangle,
      color: "text-amber-400",
      bgColor: "bg-amber-500/10",
      borderColor: "border-amber-500/20",
    },
    {
      title: "Detections",
      value: detectionsCount.toLocaleString(),
      subtitle: "Behavioral & signature signals",
      icon: Crosshair,
      color: "text-rose-400",
      bgColor: "bg-rose-500/10",
      borderColor: "border-rose-500/20",
    },
    {
      title: "Entities",
      value: entitiesCount.toLocaleString(),
      subtitle: "Unique hosts, IPs & usernames",
      icon: Users,
      color: "text-cyan-400",
      bgColor: "bg-cyan-500/10",
      borderColor: "border-cyan-500/20",
    },
    {
      title: "Active Cases",
      value: openCasesCount.toLocaleString(),
      subtitle: `${totalCasesCount} total SOC incidents`,
      icon: Briefcase,
      color: "text-emerald-400",
      bgColor: "bg-emerald-500/10",
      borderColor: "border-emerald-500/20",
    },
    {
      title: "IOC Watchlist",
      value: iocsCount.toLocaleString(),
      subtitle: "Active threat intelligence hashes/IPs",
      icon: Database,
      color: "text-purple-400",
      bgColor: "bg-purple-500/10",
      borderColor: "border-purple-500/20",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-5">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className="p-3.5 rounded-lg bg-[#111821] border border-[#243244] hover:border-[#33445c] transition-all"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-medium text-[#94a3b8]">{card.title}</span>
              <div className={`p-1.5 rounded ${card.bgColor} ${card.borderColor} border`}>
                <Icon className={`w-3.5 h-3.5 ${card.color}`} />
              </div>
            </div>
            <div className="text-2xl font-bold text-[#e8edf2] font-mono tracking-tight">
              {card.value}
            </div>
            <div className="text-[11px] text-[#94a3b8] mt-1 truncate">
              {card.subtitle}
            </div>
          </div>
        );
      })}
    </div>
  );
};
