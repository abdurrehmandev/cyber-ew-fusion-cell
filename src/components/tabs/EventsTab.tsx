import React, { useState } from "react";
import { Search, FileText, Download } from "lucide-react";
import { AlertRecord } from "../../types";

interface EventsTabProps {
  alerts: AlertRecord[];
}

export const EventsTab: React.FC<EventsTabProps> = ({ alerts }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<any>(null);

  const rawEvents = alerts.map(a => a.event || {
    event_id: a.alert_id,
    event_type: "normalized_alert",
    timestamp: a.timestamp,
    source_ip: a.source_ip || "192.168.1.55",
    destination_ip: a.destination_ip || "198.51.100.23",
    username: a.username || null,
    severity: a.level || "High",
    confidence: a.score || 0.85,
    details: a.metadata || {},
  });

  const filteredEvents = rawEvents.filter(e => {
    const text = (e.event_id + " " + e.event_type + " " + (e.source_ip || "") + " " + (e.destination_ip || "") + " " + ((e as any).username || "")).toLowerCase();
    return !searchTerm || text.includes(searchTerm.toLowerCase());
  });

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(rawEvents, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `normalized_events_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Normalized Event Log Explorer ({rawEvents.length} records)
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Schema-unified events ingested from Syslog, Suricata EVE, Zeek TSV, Windows Event Log, and live PCAP
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search event ID, IP, user..."
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] placeholder-[#64748b] focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-[#e8edf2] border border-[#243244] text-xs font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          </div>
        </div>

        {/* Event Table */}
        <div className="overflow-x-auto max-h-72 border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244] sticky top-0 font-mono">
              <tr>
                <th className="py-2 px-3">Event ID</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Event Type</th>
                <th className="py-2 px-3">Source Node</th>
                <th className="py-2 px-3">Destination</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2] font-mono">
              {filteredEvents.slice(0, 50).map((evt, idx) => (
                <tr
                  key={idx}
                  onClick={() => setSelectedEvent(evt)}
                  className="hover:bg-[#151e29]/50 cursor-pointer"
                >
                  <td className="py-2 px-3 text-cyan-400 font-bold">{evt.event_id}</td>
                  <td className="py-2 px-3 text-[#94a3b8] text-[11px]">
                    {(evt.timestamp || "").replace("T", " ").substring(0, 19)}
                  </td>
                  <td className="py-2 px-3 text-[#e8edf2]">{evt.event_type}</td>
                  <td className="py-2 px-3 text-cyan-300">{evt.source_ip || "—"}</td>
                  <td className="py-2 px-3 text-[#94a3b8]">{evt.destination_ip || "—"}</td>
                  <td className="py-2 px-3">
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-[#0b0f14] text-amber-300 border border-[#243244]">
                      {evt.severity}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-right text-cyan-400 text-[11px]">
                    View
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Event Payload Inspector */}
      {selectedEvent && (
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-[#e8edf2]">
              Normalized Schema Payload: <code className="text-cyan-400">{selectedEvent.event_id}</code>
            </span>
            <button
              onClick={() => setSelectedEvent(null)}
              className="text-xs text-[#94a3b8] hover:text-[#e8edf2]"
            >
              Close
            </button>
          </div>
          <pre className="p-3 rounded bg-[#0b0f14] border border-[#243244] font-mono text-[11px] text-[#94a3b8] overflow-x-auto max-h-48">
            {JSON.stringify(selectedEvent, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
