import React, { useState } from "react";
import { CaseRecord } from "../../types";
import { Briefcase, Search, Plus, Download, CheckCircle, Clock } from "lucide-react";

interface CasesTabProps {
  cases: CaseRecord[];
  onSaveCase: (caseData: any) => void;
}

export const CasesTab: React.FC<CasesTabProps> = ({ cases, onSaveCase }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.case_id || "");

  const filteredCases = cases.filter(c => {
    const text = (c.title + " " + c.owner + " " + c.disposition + " " + c.playbook + " " + (c.tags || []).join(" ")).toLowerCase();
    const matchesSearch = !searchTerm || text.includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === "All" || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const selectedCase = cases.find(c => c.case_id === selectedCaseId) || cases[0];

  const handleExportCases = () => {
    const blob = new Blob([JSON.stringify(cases, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc_cases_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Header & Controls */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <Briefcase className="w-4 h-4 text-emerald-400" />
              SOC Incident Case Management ({cases.length} total)
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Track containment status, evidence tags, playbook assignments, and analyst disposition
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search cases, owners, tags..."
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] placeholder-[#64748b] focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
            >
              <option value="All">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Contained">Contained</option>
              <option value="Closed">Closed</option>
            </select>

            <button
              onClick={handleExportCases}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-[#e8edf2] border border-[#243244] text-xs font-medium"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Cases</span>
            </button>
          </div>
        </div>

        {/* Cases Table */}
        <div className="overflow-x-auto max-h-72 border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244] sticky top-0">
              <tr>
                <th className="py-2 px-3">Case ID</th>
                <th className="py-2 px-3">Title</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Disposition</th>
                <th className="py-2 px-3">Owner</th>
                <th className="py-2 px-3">Playbook</th>
                <th className="py-2 px-3">Tags</th>
                <th className="py-2 px-3 text-right">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
              {filteredCases.map((c, idx) => {
                const isSelected = selectedCase?.case_id === c.case_id;
                const statusColor =
                  c.status === "Investigating"
                    ? "bg-amber-950 text-amber-300 border-amber-800"
                    : c.status === "Contained"
                    ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                    : c.status === "Closed"
                    ? "bg-[#151e29] text-[#94a3b8] border-[#243244]"
                    : "bg-cyan-950 text-cyan-300 border-cyan-800";

                return (
                  <tr
                    key={idx}
                    onClick={() => setSelectedCaseId(c.case_id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-cyan-950/40 border-l-2 border-l-cyan-400" : "hover:bg-[#151e29]/50"
                    }`}
                  >
                    <td className="py-2 px-3 font-mono font-bold text-cyan-400">{c.case_id}</td>
                    <td className="py-2 px-3 font-medium max-w-xs truncate">{c.title}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${statusColor}`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-medium text-amber-300">{c.disposition}</td>
                    <td className="py-2 px-3 text-[#94a3b8]">{c.owner}</td>
                    <td className="py-2 px-3 text-[#e8edf2]">{c.playbook}</td>
                    <td className="py-2 px-3">
                      <div className="flex flex-wrap gap-1">
                        {(c.tags || []).slice(0, 2).map((t, i) => (
                          <span key={i} className="px-1.5 py-0.2 rounded text-[10px] bg-[#151e29] text-cyan-300 border border-[#243244]">
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2 px-3 text-right font-mono text-[11px] text-[#94a3b8]">
                      {(c.updated_at || "").replace("T", " ").substring(0, 16)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Case Detail Viewer */}
      {selectedCase && (
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <div className="flex items-center justify-between mb-3">
            <div>
              <span className="text-xs font-mono text-cyan-400">{selectedCase.case_id}</span>
              <h4 className="text-sm font-semibold text-[#e8edf2]">{selectedCase.title}</h4>
            </div>
            <span className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
              {selectedCase.status}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mb-3">
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
              <span className="text-[#94a3b8] block text-[10px]">Assigned Analyst:</span>
              <span className="font-semibold text-[#e8edf2]">{selectedCase.owner}</span>
            </div>
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
              <span className="text-[#94a3b8] block text-[10px]">Threat Disposition:</span>
              <span className="font-semibold text-amber-300">{selectedCase.disposition}</span>
            </div>
            <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
              <span className="text-[#94a3b8] block text-[10px]">Response Playbook:</span>
              <span className="font-semibold text-cyan-300">{selectedCase.playbook}</span>
            </div>
          </div>

          <div className="p-3 rounded bg-[#151e29] border border-[#243244] text-xs space-y-2">
            <div className="font-semibold text-[#e8edf2]">Case Investigation Notes:</div>
            <p className="text-[#94a3b8] leading-relaxed font-mono">
              {selectedCase.notes || "No additional analyst notes recorded."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
