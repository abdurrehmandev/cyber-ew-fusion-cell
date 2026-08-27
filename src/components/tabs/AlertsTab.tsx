import React, { useState } from "react";
import { AlertRecord } from "../../types";
import { Search, Filter, ShieldAlert, CheckCircle, PlusCircle, Download, FileText, ExternalLink, ArrowRight } from "lucide-react";

interface AlertsTabProps {
  alerts: AlertRecord[];
  onSaveCase: (caseData: any) => void;
  onAddIoc: (iocData: any) => void;
}

const PLAYBOOK_OPTIONS: Record<string, string[]> = {
  "Ransomware": [
    "Isolate affected host from network via firewall / EDR",
    "Collect process tree, scheduled tasks, and recent file changes",
    "Disable compromised accounts and rotate exposed credentials",
    "Preserve encrypted file samples and ransom notes for forensics",
  ],
  "C2 Beaconing": [
    "Block destination at DNS, proxy, and perimeter firewall controls",
    "Collect endpoint network timeline and parent process hash",
    "Search for same callback destination across all telemetry",
    "Acquire memory and triage package if beaconing persists",
  ],
  "Credential Attack": [
    "Lock or reset targeted administrative/user accounts",
    "Review source host ownership and recent successful logons",
    "Check MFA fatigue, impossible travel, and password spray logs",
    "Add attacking source IP to SOC blocklist",
  ],
  "Data Exfiltration": [
    "Block outbound destination and inspect proxy/firewall logs",
    "Identify sensitive files accessed prior to transfer",
    "Review DLP, cloud staging, and archive creation evidence",
    "Escalate to incident response lead for breach assessment",
  ],
  "General Investigation": [
    "Validate alert against raw sensor telemetry",
    "Pivot on source IP, destination IP, user, and process",
    "Document evidence and containment decisions in case notes",
    "Close case with formal disposition and action item summary",
  ],
};

export const AlertsTab: React.FC<AlertsTabProps> = ({ alerts, onSaveCase, onAddIoc }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("All");
  const [selectedAlertId, setSelectedAlertId] = useState<string>(alerts[0]?.alert_id || "");

  // Form states for selected alert workflow
  const [caseStatus, setCaseStatus] = useState("Investigating");
  const [disposition, setDisposition] = useState("True Positive");
  const [owner, setOwner] = useState("Analyst (Alpha)");
  const [playbook, setPlaybook] = useState("Ransomware");
  const [notes, setNotes] = useState("");
  const [caseTags, setCaseTags] = useState("urgent, endpoint-isolation");
  const [feedback, setFeedback] = useState<string | null>(null);

  const selectedAlert = alerts.find(a => a.alert_id === selectedAlertId || a.event?.event_id === selectedAlertId) || alerts[0];

  const filteredAlerts = alerts.filter(a => {
    const text = (
      (a.alert_id || "") +
      " " +
      (a.event?.source_ip || a.source_ip || "") +
      " " +
      (a.event?.destination_ip || a.destination_ip || "") +
      " " +
      (a.event?.username || a.username || "") +
      " " +
      (a.patterns || "") +
      " " +
      (a.level || "")
    ).toLowerCase();

    const matchesSearch = !searchTerm || text.includes(searchTerm.toLowerCase());
    const matchesStatus = selectedStatus === "All" || (a.status || "New") === selectedStatus;
    return matchesSearch && matchesStatus;
  });

  const handleSelectAlert = (a: AlertRecord) => {
    const id = a.alert_id || a.event?.event_id;
    setSelectedAlertId(id);
    const pat = (a.patterns || "").toLowerCase();
    if (pat.includes("ransomware")) setPlaybook("Ransomware");
    else if (pat.includes("beacon") || pat.includes("c2")) setPlaybook("C2 Beaconing");
    else if (pat.includes("credential") || pat.includes("auth")) setPlaybook("Credential Attack");
    else if (pat.includes("exfil")) setPlaybook("Data Exfiltration");
    else setPlaybook("General Investigation");
  };

  const handleSave = () => {
    if (!selectedAlert) return;
    onSaveCase({
      alert_id: selectedAlert.alert_id || selectedAlert.event?.event_id,
      title: `Incident Investigation: ${selectedAlert.patterns || selectedAlert.event?.event_type || "Security Alert"}`,
      status: caseStatus,
      disposition,
      owner,
      playbook,
      notes,
      tags: caseTags.split(",").map(t => t.trim()).filter(Boolean),
      alert: selectedAlert,
    });
    setFeedback("Case saved and audit record generated!");
    setTimeout(() => setFeedback(null), 3000);
  };

  const handleAddIocSource = () => {
    const ip = selectedAlert?.event?.source_ip || selectedAlert?.source_ip;
    if (!ip) return;
    onAddIoc({
      value: ip,
      ioc_type: "ip",
      threat_type: selectedAlert.patterns?.split(",")[0]?.trim() || "malicious_host",
      confidence: selectedAlert.score || 0.85,
      description: `Added from Alert: ${selectedAlert.alert_id}`,
      tags: ["alert-triage", selectedAlert.level?.toLowerCase() || "high"],
    });
    setFeedback(`Source IP ${ip} added to IOC Watchlist!`);
    setTimeout(() => setFeedback(null), 3000);
  };

  const handleDownloadIncident = () => {
    if (!selectedAlert) return;
    const report = {
      generated_at: new Date().toISOString(),
      alert: selectedAlert,
      case_workflow: {
        status: caseStatus,
        owner,
        disposition,
        playbook,
        notes,
        tags: caseTags.split(",").map(t => t.trim()).filter(Boolean),
      },
      playbook_steps: PLAYBOOK_OPTIONS[playbook] || [],
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_${selectedAlert.alert_id || "alert"}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Alert Queue Table */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#e8edf2] flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Active Alert Queue
            </h3>
            <p className="text-xs text-[#94a3b8]">
              Deduplicated high-risk behavioral and correlation events requiring analyst triage
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search IP, user, pattern..."
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] placeholder-[#64748b] focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={selectedStatus}
              onChange={e => setSelectedStatus(e.target.value)}
              className="px-2.5 py-1.5 text-xs rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Contained">Contained</option>
              <option value="Closed">Closed</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-72 border border-[#243244] rounded">
          <table className="w-full text-left text-xs">
            <thead className="text-[#94a3b8] bg-[#151e29] border-b border-[#243244] sticky top-0">
              <tr>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3">Risk Score</th>
                <th className="py-2 px-3">Pattern / Signature</th>
                <th className="py-2 px-3">Source IP</th>
                <th className="py-2 px-3">Destination IP</th>
                <th className="py-2 px-3">Event Type</th>
                <th className="py-2 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2a38] text-[#e8edf2]">
              {filteredAlerts.slice(0, 30).map((alert, idx) => {
                const isSelected = (alert.alert_id || alert.event?.event_id) === (selectedAlert?.alert_id || selectedAlert?.event?.event_id);
                const sIp = alert.event?.source_ip || alert.source_ip || "192.168.1.55";
                const dIp = alert.event?.destination_ip || alert.destination_ip || "—";
                const eType = alert.event?.event_type || alert.event_type || "file_access";
                const lvl = alert.level || "High";

                const badgeColor =
                  lvl === "Critical"
                    ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                    : lvl === "High"
                    ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    : "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";

                return (
                  <tr
                    key={idx}
                    onClick={() => handleSelectAlert(alert)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-cyan-950/40 border-l-2 border-l-cyan-400" : "hover:bg-[#151e29]/60"
                    }`}
                  >
                    <td className="py-2 px-3 font-mono text-[11px] text-[#94a3b8]">
                      {(alert.timestamp || alert.event?.timestamp || "").replace("T", " ").substring(0, 19)}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${badgeColor}`}>
                        {lvl}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono font-bold text-amber-400">
                      {((alert.score || alert.threat_score?.score || 0.75) * 100).toFixed(0)}%
                    </td>
                    <td className="py-2 px-3 font-medium text-cyan-300 max-w-xs truncate">
                      {alert.patterns || "Ransomware encryption activity"}
                    </td>
                    <td className="py-2 px-3 font-mono text-[#e8edf2]">{sIp}</td>
                    <td className="py-2 px-3 font-mono text-[#94a3b8]">{dIp}</td>
                    <td className="py-2 px-3 text-[#94a3b8]">{eType}</td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          handleSelectAlert(alert);
                        }}
                        className="px-2 py-1 rounded bg-[#1e2a38] hover:bg-cyan-900/50 text-cyan-300 text-[11px]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Alert Detailed Triage & Analyst Workflow */}
      {selectedAlert && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Left: Detailed Alert Payload */}
          <div className="lg:col-span-6 p-4 rounded-lg bg-[#111821] border border-[#243244]">
            <h3 className="text-sm font-semibold text-[#e8edf2] mb-3 flex items-center justify-between">
              <span>Alert Telemetry & Forensics</span>
              <span className="font-mono text-xs text-cyan-400 font-normal">
                {selectedAlert.alert_id}
              </span>
            </h3>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-[#151e29] border border-[#243244]/60 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-[#94a3b8]">Event ID:</span>
                  <span className="font-mono text-[#e8edf2]">{selectedAlert.event?.event_id || selectedAlert.alert_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#94a3b8]">Threat Pattern:</span>
                  <span className="font-semibold text-rose-400">{selectedAlert.patterns || "Rapid file encryption"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#94a3b8]">Source Host / IP:</span>
                  <span className="font-mono text-cyan-300">{selectedAlert.event?.source_ip || selectedAlert.source_ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#94a3b8]">Destination:</span>
                  <span className="font-mono text-[#e8edf2]">{selectedAlert.event?.destination_ip || selectedAlert.destination_ip || "Internal Host"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#94a3b8]">File Path / Resource:</span>
                  <span className="font-mono text-[#e8edf2] truncate max-w-[280px]">
                    {selectedAlert.event?.file_path || selectedAlert.file_path || "C:/Users/Public/document.docx.locked"}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-xs font-semibold text-[#94a3b8] mb-1.5 block">Recommended Security Mitigations:</span>
                <ul className="space-y-1">
                  {(selectedAlert.recommended_actions || [
                    "Immediate endpoint isolation required",
                    "Block callback address at boundary gateway",
                    "Preserve forensic disk state and registry entries",
                  ]).map((act, i) => (
                    <li key={i} className="flex items-center gap-2 text-xs text-[#e8edf2]">
                      <ArrowRight className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                      <span>{act}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <span className="text-xs font-semibold text-[#94a3b8] mb-1.5 block">Raw Event JSON Details:</span>
                <pre className="p-2.5 rounded bg-[#0b0f14] border border-[#243244] font-mono text-[11px] text-[#94a3b8] overflow-x-auto max-h-40">
                  {JSON.stringify(selectedAlert.event?.details || selectedAlert.details || selectedAlert, null, 2)}
                </pre>
              </div>
            </div>
          </div>

          {/* Right: Analyst Case Workflow & Response Execution */}
          <div className="lg:col-span-6 p-4 rounded-lg bg-[#111821] border border-[#243244]">
            <h3 className="text-sm font-semibold text-[#e8edf2] mb-3 flex items-center justify-between">
              <span>Analyst Triage & Incident Workflow</span>
              {feedback && <span className="text-xs font-medium text-emerald-400 animate-pulse">{feedback}</span>}
            </h3>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[#94a3b8] mb-1">Case Status</label>
                  <select
                    value={caseStatus}
                    onChange={e => setCaseStatus(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
                  >
                    <option value="New">New</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Contained">Contained</option>
                    <option value="False Positive">False Positive</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#94a3b8] mb-1">Disposition</label>
                  <select
                    value={disposition}
                    onChange={e => setDisposition(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
                  >
                    <option value="True Positive">True Positive</option>
                    <option value="False Positive">False Positive</option>
                    <option value="Benign">Benign Activity</option>
                    <option value="Duplicate">Duplicate Incident</option>
                    <option value="Undetermined">Undetermined</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[#94a3b8] mb-1">Assigned Owner / Shift</label>
                  <input
                    type="text"
                    value={owner}
                    onChange={e => setOwner(e.target.value)}
                    placeholder="Analyst Name"
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-[#94a3b8] mb-1">Response Playbook</label>
                  <select
                    value={playbook}
                    onChange={e => setPlaybook(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
                  >
                    {Object.keys(PLAYBOOK_OPTIONS).map(pb => (
                      <option key={pb} value={pb}>{pb}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[#94a3b8] mb-1">Analyst Notes & Verification Summary</label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="What indicators were verified? What containment steps were taken?"
                  rows={3}
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500 placeholder-[#64748b]"
                />
              </div>

              <div>
                <label className="block text-[#94a3b8] mb-1">Tags (comma separated)</label>
                <input
                  type="text"
                  value={caseTags}
                  onChange={e => setCaseTags(e.target.value)}
                  placeholder="e.g. ransomware, urgent, p1"
                  className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Action Buttons */}
              <div className="grid grid-cols-3 gap-2 pt-1">
                <button
                  onClick={handleSave}
                  className="px-3 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center justify-center gap-1.5 transition-colors shadow"
                >
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Save Case</span>
                </button>

                <button
                  onClick={handleAddIocSource}
                  className="px-3 py-2 rounded bg-[#151e29] hover:bg-[#1e2a38] text-amber-300 border border-[#243244] font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>Add Source IOC</span>
                </button>

                <button
                  onClick={handleDownloadIncident}
                  className="px-3 py-2 rounded bg-[#151e29] hover:bg-[#1e2a38] text-[#e8edf2] border border-[#243244] font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export JSON</span>
                </button>
              </div>

              {/* Playbook checklist */}
              <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]/60 mt-2">
                <div className="text-[11px] font-semibold text-cyan-300 mb-1.5">
                  Playbook Guidance ({playbook}):
                </div>
                <div className="space-y-1">
                  {(PLAYBOOK_OPTIONS[playbook] || []).map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-[11px] text-[#94a3b8]">
                      <span className="font-mono text-cyan-400 font-bold">{idx + 1}.</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
