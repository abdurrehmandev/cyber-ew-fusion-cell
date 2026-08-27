import React, { useState } from "react";
import { IOCRecord } from "../../types";
import { Database, Plus, Search, Download, ShieldAlert, Tag, CheckCircle } from "lucide-react";

interface IOCTabProps {
  iocs: IOCRecord[];
  onAddIoc: (iocData: any) => void;
}

export const IOCTab: React.FC<IOCTabProps> = ({ iocs, onAddIoc }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState("All");
  const [showAddModal, setShowAddModal] = useState(false);

  // Form states
  const [value, setValue] = useState("");
  const [iocType, setIocType] = useState<"ip" | "domain" | "hash" | "user">("ip");
  const [threatType, setThreatType] = useState("c2_callback");
  const [confidence, setConfidence] = useState(0.9);
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("analyst-watchlist, threat-hunting");

  const filteredIocs = iocs.filter(ioc => {
    const text = (ioc.value + " " + ioc.threat_type + " " + (ioc.description || "") + " " + (ioc.tags || []).join(" ")).toLowerCase();
    const matchesSearch = !searchTerm || text.includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === "All" || ioc.ioc_type === typeFilter;
    return matchesSearch && matchesType;
  });

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    onAddIoc({
      value: value.trim(),
      ioc_type: iocType,
      threat_type: threatType,
      confidence,
      description,
      tags: tags.split(",").map(t => t.trim()).filter(Boolean),
    });
    setValue("");
    setDescription("");
    setShowAddModal(false);
  };

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat_intel_iocs_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Header Bar */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Database className="w-4 h-4 text-purple-400" />
              Local Threat Intelligence & IOC Watchlist ({iocs.length})
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Active indicators correlated in real-time during pipeline telemetry normalization and threat scoring
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search IP, domain, hash, threat type..."
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] placeholder-[#64748b] focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
            >
              <option value="All">All Types</option>
              <option value="ip">IP Addresses</option>
              <option value="domain">Domains</option>
              <option value="hash">File Hashes</option>
              <option value="user">Usernames</option>
            </select>

            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium transition-colors shadow"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add IOC</span>
            </button>

            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-[#e8edf2] border border-[#243244] text-xs font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          </div>
        </div>

        {/* IOC Table */}
        <div className="overflow-x-auto max-h-80 border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244] sticky top-0">
              <tr>
                <th className="py-2 px-3">Indicator Value</th>
                <th className="py-2 px-3">Type</th>
                <th className="py-2 px-3">Threat Classification</th>
                <th className="py-2 px-3">Confidence</th>
                <th className="py-2 px-3">Description</th>
                <th className="py-2 px-3">Tags</th>
                <th className="py-2 px-3 text-right">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
              {filteredIocs.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-[#151e29]/50">
                  <td className="py-2 px-3 font-mono font-bold text-cyan-300">{ioc.value}</td>
                  <td className="py-2 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-semibold bg-[#0b0f14] text-[#94a3b8] border border-[#243244]">
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-medium text-rose-300">{ioc.threat_type}</td>
                  <td className="py-2 px-3 font-mono font-bold text-amber-400">
                    {((ioc.confidence ?? 0.8) * 100).toFixed(0)}%
                  </td>
                  <td className="py-2 px-3 text-[#94a3b8] max-w-xs truncate">{ioc.description}</td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {(ioc.tags || []).map((t, i) => (
                        <span key={i} className="px-1.5 py-0.2 rounded text-[10px] bg-[#151e29] text-purple-300 border border-[#243244]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-3 text-right font-mono text-[11px] text-[#94a3b8]">
                    {(ioc.last_seen || "").replace("T", " ").substring(0, 16)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111821] border border-[#243244] rounded-lg p-5 shadow-2xl">
            <h3 className="text-sm font-semibold text-[#e8edf2] mb-3 flex items-center gap-2">
              <Plus className="w-4 h-4 text-purple-400" />
              Add Threat Intelligence Indicator
            </h3>

            <form onSubmit={handleAdd} className="space-y-3 text-xs">
              <div>
                <label className="block text-[#94a3b8] mb-1">Indicator Value (IP / Domain / Hash)</label>
                <input
                  type="text"
                  required
                  value={value}
                  onChange={e => setValue(e.target.value)}
                  placeholder="e.g. 198.51.100.23 or evil-domain.org"
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[#94a3b8] mb-1">IOC Type</label>
                  <select
                    value={iocType}
                    onChange={e => setIocType(e.target.value as any)}
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="hash">SHA256 Hash</option>
                    <option value="user">Compromised User</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#94a3b8] mb-1">Threat Type</label>
                  <input
                    type="text"
                    value={threatType}
                    onChange={e => setThreatType(e.target.value)}
                    placeholder="e.g. c2_beacon, ransomware"
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[#94a3b8] mb-1">Confidence Score (0.0 - 1.0)</label>
                <input
                  type="number"
                  min="0.1"
                  max="1.0"
                  step="0.05"
                  value={confidence}
                  onChange={e => setConfidence(parseFloat(e.target.value))}
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] font-mono"
                />
              </div>

              <div>
                <label className="block text-[#94a3b8] mb-1">Description / Context</label>
                <input
                  type="text"
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder="Observed in outbound port 443 callback"
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
                />
              </div>

              <div>
                <label className="block text-[#94a3b8] mb-1">Tags (comma separated)</label>
                <input
                  type="text"
                  value={tags}
                  onChange={e => setTags(e.target.value)}
                  placeholder="analyst-added, priority-high"
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded bg-[#151e29] text-[#94a3b8] hover:text-[#e8edf2] text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium shadow"
                >
                  Save IOC Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
