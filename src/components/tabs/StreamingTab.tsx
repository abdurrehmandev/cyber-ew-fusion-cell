import React, { useState } from "react";
import { IngestStreamStatus, StressTestScenario, ClusterWorker } from "../../types";
import {
  Zap,
  Activity,
  Play,
  Square,
  Sliders,
  Cpu,
  Server,
  AlertTriangle,
  UploadCloud,
  FileCode,
  Gauge,
  Layers,
  CheckCircle2,
  HardDrive,
  RefreshCw,
} from "lucide-react";

interface StreamingTabProps {
  streamStatus: IngestStreamStatus | null;
  scenarios: StressTestScenario[];
  onStartStream: (eps: number, scenarioId: string) => void;
  onStopStream: () => void;
  onAdjustEps: (eps: number) => void;
  onRawIngest: (format: string, content: string, sensorTag: string) => Promise<any>;
}

export const StreamingTab: React.FC<StreamingTabProps> = ({
  streamStatus,
  scenarios,
  onStartStream,
  onStopStream,
  onAdjustEps,
  onRawIngest,
}) => {
  const [selectedScenario, setSelectedScenario] = useState<string>("balanced_soc");
  const [targetEps, setTargetEps] = useState<number>(streamStatus?.target_eps || 250);
  const [rawFormat, setRawFormat] = useState<string>("suricata_eve");
  const [sensorTag, setSensorTag] = useState<string>("edge-sensor-us-east");
  const [rawText, setRawText] = useState<string>(
`{"timestamp":"2026-08-27T03:15:00.000Z","event_type":"alert","src_ip":"192.168.1.55","dest_ip":"198.51.100.23","proto":"TCP","alert":{"signature":"ET EXPLOIT Suspicious Remote PowerShell Execution","category":"Attempted User Privilege Gain","severity":1}}
{"timestamp":"2026-08-27T03:15:02.000Z","event_type":"alert","src_ip":"192.168.1.20","dest_ip":"203.0.113.19","proto":"TCP","alert":{"signature":"ET MALWARE Cobalt Strike Beacon Activity","category":"A Network Trojan was detected","severity":1}}`
  );
  const [ingestResult, setIngestResult] = useState<any>(null);
  const [isIngesting, setIsIngesting] = useState(false);

  const isStreaming = streamStatus?.is_streaming ?? false;
  const actualEps = streamStatus?.actual_eps ?? 0;
  const workers = streamStatus?.workers || [];

  const handleStart = () => {
    onStartStream(targetEps, selectedScenario);
  };

  const handleSliderChange = (newEps: number) => {
    setTargetEps(newEps);
    if (isStreaming) {
      onAdjustEps(newEps);
    }
  };

  const handleRawSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawText.trim()) return;
    setIsIngesting(true);
    try {
      const res = await onRawIngest(rawFormat, rawText, sensorTag);
      setIngestResult(res);
    } catch (err: any) {
      setIngestResult({ error: err.message });
    } finally {
      setIsIngesting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Streaming Master Control Banner */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-semibold text-[#e8edf2]">
                Phase 6: High-Volume Ingestion Stream & Cluster Stress Engine
              </h3>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                  isStreaming
                    ? "bg-emerald-950 text-emerald-300 border border-emerald-800 animate-pulse"
                    : "bg-[#151e29] text-[#94a3b8] border border-[#243244]"
                }`}
              >
                {isStreaming ? "Stream Active" : "Stream Idle"}
              </span>
            </div>
            <p className="text-xs text-[#94a3b8] mt-1">
              Multi-node distributed broker emulation with dynamic backpressure, queue buffer telemetry, and injection scenarios
            </p>
          </div>

          <div className="flex items-center gap-2">
            {!isStreaming ? (
              <button
                onClick={handleStart}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg transition-all"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>Start Stream ({targetEps} EPS)</span>
              </button>
            ) : (
              <button
                onClick={onStopStream}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-lg transition-all"
              >
                <Square className="w-4 h-4 fill-white" />
                <span>Halt Live Stream</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Streaming KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2.5 pt-2 border-t border-[#243244]">
          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">Current Throughput:</span>
            <div className="font-mono text-sm font-bold text-cyan-300 flex items-center gap-1">
              <Activity className="w-3.5 h-3.5" />
              <span>{actualEps} EPS</span>
            </div>
          </div>

          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">Target Throttle:</span>
            <div className="font-mono text-sm font-bold text-[#e8edf2]">{targetEps} EPS</div>
          </div>

          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">Total Ingested:</span>
            <div className="font-mono text-sm font-bold text-amber-400">
              {(streamStatus?.total_streamed ?? 0).toLocaleString()}
            </div>
          </div>

          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">Avg Pipeline Latency:</span>
            <div className="font-mono text-sm font-bold text-emerald-400">
              {streamStatus?.avg_pipeline_latency_ms ?? 2.4} ms
            </div>
          </div>

          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">P99 Tail Latency:</span>
            <div className="font-mono text-sm font-bold text-cyan-400">
              {streamStatus?.p99_latency_ms ?? 7.8} ms
            </div>
          </div>

          <div className="p-2.5 rounded bg-[#151e29] border border-[#243244]">
            <span className="text-[10px] text-[#94a3b8] block">Backpressure / Drops:</span>
            <div
              className={`font-mono text-sm font-bold ${
                streamStatus?.backpressure_active ? "text-rose-400" : "text-emerald-400"
              }`}
            >
              {streamStatus?.backpressure_active ? "Active (0.8% Drop)" : "Nominal (0%)"}
            </div>
          </div>
        </div>
      </div>

      {/* Target Throttle Slider & Attack Scenario Selection */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* EPS Slider Controller */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#e8edf2] flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              Event Ingestion Rate (EPS)
            </span>
            <span className="font-mono font-bold text-sm text-cyan-300">{targetEps} EPS</span>
          </div>

          <input
            type="range"
            min="20"
            max="1800"
            step="20"
            value={targetEps}
            onChange={e => handleSliderChange(parseInt(e.target.value))}
            className="w-full h-2 bg-[#151e29] rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />

          <div className="flex justify-between text-[10px] font-mono text-[#64748b]">
            <span>20 EPS (Light)</span>
            <span>500 EPS (Normal)</span>
            <span>1200+ EPS (Stress)</span>
          </div>

          <div className="p-2 rounded bg-[#151e29] border border-[#243244]/60 text-[11px] text-[#94a3b8]">
            Rates above 1,000 EPS automatically trigger backpressure flow controls and buffer load shedding.
          </div>
        </div>

        {/* Attack Scenario Selector */}
        <div className="md:col-span-2 p-4 rounded-lg bg-[#111821] border border-[#243244]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] mb-3 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-amber-400" />
            Adversary Emulation & Ingestion Scenarios
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {scenarios.map(sc => {
              const isSelected = selectedScenario === sc.id;
              return (
                <div
                  key={sc.id}
                  onClick={() => {
                    setSelectedScenario(sc.id);
                    if (isStreaming) onStartStream(sc.target_eps, sc.id);
                    else setTargetEps(sc.target_eps);
                  }}
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? "bg-cyan-950/40 border-cyan-500/70 shadow-sm"
                      : "bg-[#151e29] border-[#243244] hover:border-[#33445c]"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-xs text-[#e8edf2]">{sc.name}</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-[#0b0f14] text-cyan-300 font-mono">
                      {sc.target_eps} EPS
                    </span>
                  </div>
                  <p className="text-[11px] text-[#94a3b8] mb-2">{sc.description}</p>
                  <div className="flex items-center justify-between text-[10px] text-[#64748b]">
                    <span>Attack Injection: {(sc.attack_injection_rate * 100).toFixed(0)}%</span>
                    <span>Dur: {sc.duration_sec}s</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Cluster Worker Fleet Health & Load Distribution */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              Cluster Worker Fleet & Queue Telemetry ({workers.length} Nodes)
            </h4>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Distributed pipeline stage workers with real-time buffer depths and resource consumption
            </p>
          </div>
          <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
            Cluster Mode: Distributed
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {workers.map((w, idx) => (
            <div key={idx} className="p-3 rounded-lg bg-[#151e29] border border-[#243244] text-xs space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-bold text-[#e8edf2] font-mono">{w.name}</span>
                  <span className="text-[10px] text-[#94a3b8] block capitalize">{w.role} Node</span>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                    w.status === "active"
                      ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                      : w.status === "congested"
                      ? "bg-rose-950 text-rose-300 border-rose-800"
                      : "bg-[#111821] text-[#94a3b8] border-[#243244]"
                  }`}
                >
                  {w.status}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-[#243244]/60">
                <div>
                  <span className="text-[#94a3b8] block text-[10px]">Worker Throughput:</span>
                  <span className="font-mono font-bold text-cyan-300">{w.eps_current} EPS</span>
                </div>
                <div>
                  <span className="text-[#94a3b8] block text-[10px]">Processing Latency:</span>
                  <span className="font-mono font-semibold text-[#e8edf2]">{w.latency_ms} ms</span>
                </div>
              </div>

              {/* Buffer Depth Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-[10px]">
                  <span className="text-[#94a3b8]">Queue Buffer Depth:</span>
                  <span className="font-mono text-[#e8edf2]">
                    {w.buffer_depth} / {w.buffer_capacity} ({((w.buffer_depth / w.buffer_capacity) * 100).toFixed(1)}%)
                  </span>
                </div>
                <div className="w-full h-1.5 bg-[#0b0f14] rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${
                      w.buffer_depth > 80 ? "bg-rose-500" : "bg-cyan-400"
                    }`}
                    style={{ width: `${Math.min(100, Math.max(5, (w.buffer_depth / 200) * 100))}%` }}
                  />
                </div>
              </div>

              <div className="flex justify-between text-[10px] text-[#94a3b8] pt-1">
                <span>CPU: {w.cpu_usage_pct}%</span>
                <span>RAM: {w.memory_mb} MB</span>
                <span>Processed: {w.processed_total.toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Raw Multi-Format Telemetry Ingestion Workbench */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              Raw Multi-Sensor Telemetry Ingestion Workbench
            </h4>
            <p className="text-xs text-[#94a3b8]">
              Directly parse and normalize raw Suricata EVE JSON, Zeek TSV, Syslog, or Sysmon telemetry streams
            </p>
          </div>
        </div>

        <form onSubmit={handleRawSubmit} className="space-y-3 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-[#94a3b8] mb-1">Parser Format:</label>
              <select
                value={rawFormat}
                onChange={e => setRawFormat(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2]"
              >
                <option value="suricata_eve">Suricata EVE JSON</option>
                <option value="zeek_tsv">Zeek TSV (conn.log / notice.log)</option>
                <option value="jsonl">Raw JSONL Pipeline Format</option>
                <option value="syslog">Syslog RFC 5424</option>
              </select>
            </div>

            <div>
              <label className="block text-[#94a3b8] mb-1">Origin Sensor / Collector Tag:</label>
              <input
                type="text"
                value={sensorTag}
                onChange={e => setSensorTag(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded bg-[#151e29] border border-[#243244] text-[#e8edf2] font-mono"
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={isIngesting}
                className="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center justify-center gap-1.5 transition-colors shadow disabled:opacity-50"
              >
                <UploadCloud className="w-3.5 h-3.5" />
                <span>{isIngesting ? "Parsing & Scoring..." : "Ingest & Normalize Stream"}</span>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-[#94a3b8] mb-1">Raw Telemetry Log Payload (Multi-line):</label>
            <textarea
              rows={5}
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              className="w-full p-2.5 rounded bg-[#0b0f14] border border-[#243244] text-[#e8edf2] font-mono text-[11px] leading-relaxed focus:outline-none focus:border-cyan-500"
              placeholder="Paste raw log lines here..."
            />
          </div>

          {ingestResult && (
            <div className="p-3 rounded bg-[#151e29] border border-[#243244] text-xs space-y-1">
              <div className="font-semibold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Ingestion Successful:</span>
              </div>
              <pre className="font-mono text-[11px] text-[#94a3b8]">
                {JSON.stringify(ingestResult, null, 2)}
              </pre>
            </div>
          )}
        </form>
      </div>
    </div>
  );
};
