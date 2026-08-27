import React, { useState } from "react";
import { Playbook, PlaybookRun } from "../../types";
import { Cpu, Play, CheckCircle2, ShieldAlert, AlertTriangle, Check, RotateCw } from "lucide-react";

interface AutomationTabProps {
  playbooks: Playbook[];
  playbookRuns: PlaybookRun[];
  onRunPlaybook: (playbookId: string, approved: boolean) => Promise<any>;
}

export const AutomationTab: React.FC<AutomationTabProps> = ({
  playbooks,
  playbookRuns,
  onRunPlaybook,
}) => {
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>(playbooks[0]?.playbook_id || "PB-001");
  const [approveDestructive, setApproveDestructive] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [latestResult, setLatestResult] = useState<any>(null);

  const selectedPlaybook = playbooks.find(p => p.playbook_id === selectedPlaybookId) || playbooks[0];

  const handleExecute = async () => {
    if (!selectedPlaybook) return;
    setIsRunning(true);
    try {
      const result = await onRunPlaybook(selectedPlaybook.playbook_id, approveDestructive);
      setLatestResult(result);
    } catch (err) {
      console.error(err);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Playbook List & Execution Console */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Playbooks Catalog */}
        <div className="lg:col-span-6 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h3 className="text-sm font-semibold text-[#e8edf2] mb-3 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Active SOAR Response Playbooks ({playbooks.length})
          </h3>
          <p className="text-xs text-[#94a3b8] mb-3">
            Destructive containment actions require explicit operator sign-off or stay simulated dry-run.
          </p>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {playbooks.map(pb => {
              const isSelected = pb.playbook_id === selectedPlaybookId;
              const hasDestructive = pb.actions.some(a => a.destructive);

              return (
                <div
                  key={pb.playbook_id}
                  onClick={() => {
                    setSelectedPlaybookId(pb.playbook_id);
                    setLatestResult(null);
                  }}
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? "bg-cyan-950/30 border-cyan-500/50 shadow-sm"
                      : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-cyan-400">{pb.playbook_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-[#0b0f14] text-[#94a3b8] border border-[#243244]">
                      {pb.category}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-[#e8edf2] mb-1">{pb.name}</div>
                  <p className="text-[11px] text-[#94a3b8] line-clamp-2">{pb.description}</p>

                  <div className="mt-2 flex items-center justify-between text-[11px]">
                    <span className="text-[#64748b]">Trigger: {pb.trigger}</span>
                    <span className="text-cyan-300 font-mono">{pb.actions.length} actions</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Selected Playbook Workflow Inspector & Run Trigger */}
        <div className="lg:col-span-6 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          {selectedPlaybook ? (
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[11px] text-cyan-400 font-mono">{selectedPlaybook.playbook_id}</span>
                  <h4 className="text-sm font-semibold text-[#e8edf2]">{selectedPlaybook.name}</h4>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {selectedPlaybook.category}
                </span>
              </div>

              <div className="p-3 rounded bg-[#151e29] border border-[#243244]">
                <div className="font-medium text-[#e8edf2] mb-1">Action Flow Definition:</div>
                <div className="space-y-2 mt-2">
                  {selectedPlaybook.actions.map((act, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between p-2 rounded bg-[#0b0f14] border border-[#243244]"
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 flex items-center justify-center font-mono text-[10px]">
                          {i + 1}
                        </span>
                        <div>
                          <span className="font-mono text-[#e8edf2]">{act.action}</span>
                          <span className="text-[#94a3b8] text-[11px] ml-2">Target: {act.target}</span>
                        </div>
                      </div>
                      {act.destructive ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> Destructive
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800">
                          Non-Destructive
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Execution Approval Form */}
              <div className="p-3 rounded bg-[#151e29] border border-[#243244] space-y-2.5">
                <label className="flex items-center gap-2 text-xs text-[#e8edf2] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={approveDestructive}
                    onChange={e => setApproveDestructive(e.target.checked)}
                    className="rounded border-[#243244] text-cyan-500 focus:ring-0"
                  />
                  <span className="font-medium">Approve destructive mitigation actions (EDR host quarantine / IP block)</span>
                </label>

                <button
                  onClick={handleExecute}
                  disabled={isRunning}
                  className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center justify-center gap-2 transition-colors shadow disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{isRunning ? "Running Playbook..." : `Execute ${selectedPlaybook.playbook_id}`}</span>
                </button>
              </div>

              {/* Latest Result */}
              {latestResult && (
                <div className="p-3 rounded bg-cyan-950/20 border border-cyan-800/60 space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Run Status: {latestResult.status}</span>
                  </div>
                  <pre className="text-[#94a3b8] overflow-x-auto max-h-32 p-2 bg-[#0b0f14] rounded">
                    {JSON.stringify(latestResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-[#94a3b8]">
              Select a playbook from the list to view actions.
            </div>
          )}
        </div>
      </div>

      {/* Recent Automation Executions */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <h3 className="text-sm font-semibold text-[#e8edf2] mb-3">
          Recent Automation Execution History ({playbookRuns.length} runs)
        </h3>

        <div className="overflow-x-auto border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244]">
              <tr>
                <th className="py-2 px-3">Run ID</th>
                <th className="py-2 px-3">Playbook</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Operator</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Actions Executed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2] font-mono">
              {playbookRuns.map((run, i) => (
                <tr key={i} className="hover:bg-[#151e29]/50">
                  <td className="py-2 px-3 text-cyan-400 font-bold">{run.run_id}</td>
                  <td className="py-2 px-3 font-semibold text-[#e8edf2]">{run.playbook_id}</td>
                  <td className="py-2 px-3 text-[#94a3b8]">
                    {(run.timestamp || "").replace("T", " ").substring(0, 19)}
                  </td>
                  <td className="py-2 px-3 text-[#94a3b8]">{run.actor}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        run.approved
                          ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                          : "bg-amber-950 text-amber-300 border-amber-800"
                      }`}
                    >
                      {run.status}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-cyan-300 text-[11px]">
                    {run.actions_executed?.map(a => a.action).join(", ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
