import React, { useState, useEffect, useRef } from "react";
import {
  Network,
  UploadCloud,
  FileSearch,
  ShieldAlert,
  Binary,
  Layers,
  Search,
  Clock,
  ArrowRight,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Code2,
  Lock,
} from "lucide-react";
import { PCAPDissectionResult, PCAPPacket, PCAPSessionFlow } from "../../types";

export const PCAPDissectorTab: React.FC = () => {
  const [selectedPcap, setSelectedPcap] = useState<string>("apt29-cobalt-strike-c2.pcap");
  const [pcapList, setPcapList] = useState<{ name: string; total_packets: number; detected_threats: string[] }[]>([]);
  const [dissection, setDissection] = useState<PCAPDissectionResult | null>(null);
  const [selectedFrame, setSelectedFrame] = useState<PCAPPacket | null>(null);
  const [activeSubView, setActiveSubView] = useState<"packets" | "flows">("packets");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const fetchDissection = async (pcapName: string) => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/pcap/dissect/${pcapName}`);
      const data: PCAPDissectionResult = await res.json();
      setDissection(data);
      if (data.packets && data.packets.length > 0) {
        setSelectedFrame(data.packets[0]);
      }
    } catch (err) {
      console.error("Error fetching PCAP dissection:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchSamples = async () => {
    try {
      const res = await fetch("/api/pcap/samples");
      const list = await res.json();
      setPcapList(list);
    } catch (err) {
      console.error("Error fetching PCAP sample list:", err);
    }
  };

  useEffect(() => {
    fetchSamples();
    fetchDissection(selectedPcap);
  }, []);

  const handleSelectPcap = (name: string) => {
    setSelectedPcap(name);
    fetchDissection(name);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsLoading(true);
    try {
      const text = await file.text();
      const res = await fetch("/api/pcap/dissect-custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, content: text }),
      });
      const data = await res.json();
      setDissection(data);
      setSelectedPcap(file.name);
      if (data.packets?.length > 0) {
        setSelectedFrame(data.packets[0]);
      }
    } catch (err) {
      console.error("Error parsing uploaded PCAP:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const filteredPackets = dissection?.packets.filter((pkt) => {
    if (!pkt) return false;
    const protocolStr = pkt.protocol || "";
    if (protocolFilter !== "ALL" && !protocolStr.includes(protocolFilter)) return false;
    if (!searchFilter) return true;
    const s = searchFilter.toLowerCase();
    return (
      (pkt.info || "").toLowerCase().includes(s) ||
      (pkt.source_ip || "").toLowerCase().includes(s) ||
      (pkt.dest_ip || "").toLowerCase().includes(s) ||
      protocolStr.toLowerCase().includes(s) ||
      (pkt.dpi_findings?.ja3_hash && pkt.dpi_findings.ja3_hash.toLowerCase().includes(s)) ||
      (pkt.dpi_findings?.sni_server_name && pkt.dpi_findings.sni_server_name.toLowerCase().includes(s)) ||
      (pkt.dpi_findings?.dns_query_name && pkt.dpi_findings.dns_query_name.toLowerCase().includes(s))
    );
  }) || [];

  return (
    <div className="space-y-4">
      {/* Top Header Card */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[#e8edf2] flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Live PCAP & Deep Packet Inspection (DPI) Dissector
          </h2>
          <p className="text-xs text-[#94a3b8]">
            Dissect full-stream packet captures, extract JA3/JA4 TLS hashes, decode DNS tunnels, carve HTTP headers, and reassemble TCP flows
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Sample PCAPs Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[#94a3b8]">Sample:</span>
            <select
              value={selectedPcap}
              onChange={(e) => handleSelectPcap(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-[#151e29] text-[#e8edf2] rounded border border-[#243244] focus:outline-none focus:border-cyan-500"
            >
              {pcapList.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name} ({p.total_packets} pkts)
                </option>
              ))}
            </select>
          </div>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
            accept=".pcap,.pcapng,.cap,.json,.txt"
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151e29] hover:bg-[#1e2a38] text-cyan-300 text-xs font-medium border border-[#243244] transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            Upload PCAP
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      {dissection && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-[#111821] border border-[#243244]">
            <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-1">Total Packets</div>
            <div className="text-base font-bold text-[#e8edf2]">{dissection.total_packets}</div>
            <div className="text-[10px] text-[#94a3b8]">{Math.round(dissection.total_bytes / 1024)} KB payload</div>
          </div>

          <div className="p-3 rounded-lg bg-[#111821] border border-[#243244]">
            <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-1">Anomalous Packets</div>
            <div className="text-base font-bold text-red-400">{dissection.anomalous_packets_count}</div>
            <div className="text-[10px] text-red-400/80">DPI Rule Triggered</div>
          </div>

          <div className="p-3 rounded-lg bg-[#111821] border border-[#243244]">
            <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-1">TLS / SSL Sessions</div>
            <div className="text-base font-bold text-cyan-400">{dissection.dpi_summary.tls_sessions}</div>
            <div className="text-[10px] text-[#94a3b8]">{dissection.dpi_summary.suspicious_ja3_hashes.length} suspicious JA3</div>
          </div>

          <div className="p-3 rounded-lg bg-[#111821] border border-[#243244]">
            <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-1">DNS Tunnels</div>
            <div className="text-base font-bold text-amber-400">{dissection.dpi_summary.dns_tunnels_flagged}</div>
            <div className="text-[10px] text-[#94a3b8]">Entropy &gt; 3.2</div>
          </div>

          <div className="p-3 rounded-lg bg-[#111821] border border-[#243244]">
            <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-1">Capture Duration</div>
            <div className="text-base font-bold text-emerald-400">{dissection.duration_seconds}s</div>
            <div className="text-[10px] text-[#94a3b8]">Full PCAP Dissection</div>
          </div>
        </div>
      )}

      {/* Detected Threat Alerts Banner */}
      {dissection && dissection.detected_threats && dissection.detected_threats.length > 0 && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-200">
          <div className="font-semibold text-red-300 mb-1.5 flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <span>Deep Packet Inspection (DPI) Findings:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {dissection.detected_threats.map((threat, idx) => (
              <span key={idx} className="px-2 py-0.5 rounded bg-red-950/60 border border-red-500/40 text-[11px]">
                {threat}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Main Wireshark-Style Inspection Section */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-3">
        {/* Sub-view Navigation & Filters */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 pb-3 border-b border-[#1e2a38]">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveSubView("packets")}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                activeSubView === "packets"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                  : "bg-[#151e29] text-[#94a3b8] hover:text-[#e8edf2]"
              }`}
            >
              Packet List ({filteredPackets.length})
            </button>
            <button
              onClick={() => setActiveSubView("flows")}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                activeSubView === "flows"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                  : "bg-[#151e29] text-[#94a3b8] hover:text-[#e8edf2]"
              }`}
            >
              Reconstructed Flows ({dissection?.flows?.length || 0})
            </button>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-56">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
              <input
                type="text"
                placeholder="Filter by IP, JA3, SNI, Info..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full pl-8 pr-3 py-1 text-xs bg-[#0b0f14] text-[#e8edf2] rounded border border-[#243244] focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="px-2 py-1 text-xs bg-[#151e29] text-[#e8edf2] rounded border border-[#243244] focus:outline-none"
            >
              <option value="ALL">All Proto</option>
              <option value="TLS">TLS</option>
              <option value="DNS">DNS</option>
              <option value="HTTP">HTTP</option>
              <option value="Kerberos">Kerberos</option>
              <option value="TCP">TCP</option>
            </select>
          </div>
        </div>

        {activeSubView === "packets" && (
          <div className="space-y-4">
            {/* Packet Table (Top Pane) */}
            <div className="overflow-x-auto max-h-64 border border-[#243244] rounded bg-[#0b0f14]">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#151e29] text-[#94a3b8] font-mono sticky top-0 border-b border-[#243244]">
                  <tr>
                    <th className="p-2 w-12">No.</th>
                    <th className="p-2 w-20">Time</th>
                    <th className="p-2 w-32">Source</th>
                    <th className="p-2 w-32">Destination</th>
                    <th className="p-2 w-20">Protocol</th>
                    <th className="p-2 w-16">Length</th>
                    <th className="p-2">Info</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2a38] font-mono text-[11px]">
                  {filteredPackets.map((pkt) => {
                    const isSelected = selectedFrame?.frame_number === pkt.frame_number;
                    return (
                      <tr
                        key={pkt.frame_number}
                        onClick={() => setSelectedFrame(pkt)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? "bg-cyan-500/20 text-cyan-200 border-l-2 border-cyan-400"
                            : pkt.is_anomalous
                            ? "hover:bg-red-500/10 text-red-300"
                            : "hover:bg-[#151e29]/70 text-[#cbd5e1]"
                        }`}
                      >
                        <td className="p-2 font-bold">{pkt.frame_number}</td>
                        <td className="p-2 text-[#94a3b8]">{pkt.time_relative_s.toFixed(3)}s</td>
                        <td className="p-2 truncate">
                          {pkt.source_ip}:{pkt.source_port}
                        </td>
                        <td className="p-2 truncate">
                          {pkt.dest_ip}:{pkt.dest_port}
                        </td>
                        <td className="p-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              pkt.protocol.startsWith("TLS")
                                ? "bg-purple-500/20 text-purple-300"
                                : pkt.protocol === "DNS"
                                ? "bg-amber-500/20 text-amber-300"
                                : pkt.protocol.startsWith("HTTP")
                                ? "bg-emerald-500/20 text-emerald-300"
                                : pkt.protocol === "Kerberos"
                                ? "bg-red-500/20 text-red-300"
                                : "bg-slate-500/20 text-slate-300"
                            }`}
                          >
                            {pkt.protocol}
                          </span>
                        </td>
                        <td className="p-2">{pkt.length_bytes}</td>
                        <td className="p-2 truncate max-w-md font-sans">
                          {pkt.info}
                          {pkt.is_anomalous && (
                            <span className="ml-2 px-1.5 py-0.2 rounded bg-red-600 text-white text-[9px] font-bold">
                              THREAT
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Selected Frame Dissection (Middle Pane) & Hex Dump (Bottom Pane) */}
            {selectedFrame && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Protocol Tree */}
                <div className="p-3.5 rounded bg-[#0b0f14] border border-[#243244] space-y-2.5 text-xs font-mono">
                  <div className="text-xs font-semibold text-cyan-300 flex items-center justify-between pb-1 border-b border-[#1e2a38]">
                    <span className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      Frame #{selectedFrame.frame_number} Protocol Dissection Tree
                    </span>
                    <span className="text-[10px] text-[#94a3b8] font-mono">{selectedFrame.length_bytes} bytes on wire</span>
                  </div>

                  <div className="space-y-2 text-[11px]">
                    {/* Layer 2: Ethernet */}
                    <div className="p-2 rounded bg-[#111821] border border-[#1e2a38]">
                      <div className="text-[#94a3b8] font-bold">▶ Ethernet II (MAC Layer)</div>
                      <div className="pl-3 text-slate-300 space-y-0.5 mt-1">
                        <div>Source MAC: {selectedFrame.source_mac}</div>
                        <div>Destination MAC: {selectedFrame.dest_mac}</div>
                        <div>Type: IPv4 (0x0800)</div>
                      </div>
                    </div>

                    {/* Layer 3: IPv4 */}
                    <div className="p-2 rounded bg-[#111821] border border-[#1e2a38]">
                      <div className="text-[#94a3b8] font-bold">▶ Internet Protocol Version 4</div>
                      <div className="pl-3 text-slate-300 space-y-0.5 mt-1">
                        <div>Source IP: {selectedFrame.source_ip}</div>
                        <div>Destination IP: {selectedFrame.dest_ip}</div>
                        <div>TTL: 64 | Header Length: 20 bytes</div>
                      </div>
                    </div>

                    {/* Layer 4: Transport */}
                    <div className="p-2 rounded bg-[#111821] border border-[#1e2a38]">
                      <div className="text-[#94a3b8] font-bold">▶ Transport Layer ({selectedFrame.protocol.split("/")[0]})</div>
                      <div className="pl-3 text-slate-300 space-y-0.5 mt-1">
                        <div>Source Port: {selectedFrame.source_port}</div>
                        <div>Destination Port: {selectedFrame.dest_port}</div>
                        {selectedFrame.flags && <div>Flags: {selectedFrame.flags.join(", ")}</div>}
                      </div>
                    </div>

                    {/* Layer 7: Application & DPI Findings */}
                    {selectedFrame.dpi_findings && (
                      <div className="p-2 rounded bg-[#151e29] border border-cyan-500/40">
                        <div className="text-cyan-300 font-bold flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                          <span>DPI Deep Analysis &amp; Fingerprints</span>
                        </div>
                        <div className="pl-3 text-[#e8edf2] space-y-1 mt-1.5 font-mono text-[10px]">
                          {selectedFrame.dpi_findings.ja3_hash && (
                            <div>
                              <span className="text-cyan-400">JA3 Hash:</span> {selectedFrame.dpi_findings.ja3_hash}
                            </div>
                          )}
                          {selectedFrame.dpi_findings.ja4_hash && (
                            <div>
                              <span className="text-cyan-400">JA4 Fingerprint:</span> {selectedFrame.dpi_findings.ja4_hash}
                            </div>
                          )}
                          {selectedFrame.dpi_findings.sni_server_name && (
                            <div>
                              <span className="text-emerald-400">TLS Server Name (SNI):</span> {selectedFrame.dpi_findings.sni_server_name}
                            </div>
                          )}
                          {selectedFrame.dpi_findings.dns_query_name && (
                            <div>
                              <span className="text-amber-400">DNS Query:</span> {selectedFrame.dpi_findings.dns_query_name} ({selectedFrame.dpi_findings.dns_query_type})
                            </div>
                          )}
                          {selectedFrame.dpi_findings.dns_entropy && (
                            <div>
                              <span className="text-red-400">Calculated Subdomain Entropy:</span> {selectedFrame.dpi_findings.dns_entropy} bits
                            </div>
                          )}
                          {selectedFrame.dpi_findings.http_method && (
                            <div>
                              <span className="text-emerald-400">HTTP Method:</span> {selectedFrame.dpi_findings.http_method} {selectedFrame.dpi_findings.http_uri}
                            </div>
                          )}
                          {selectedFrame.dpi_findings.cobalt_strike_watermark && (
                            <div className="text-red-400 font-bold">
                              <span>⚠️ Cobalt Strike Watermark:</span> {selectedFrame.dpi_findings.cobalt_strike_watermark}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Hex Dump & Stream ASCII Inspector */}
                <div className="p-3.5 rounded bg-[#0b0f14] border border-[#243244] space-y-2.5 font-mono text-xs">
                  <div className="text-xs font-semibold text-emerald-400 flex items-center justify-between pb-1 border-b border-[#1e2a38]">
                    <span className="flex items-center gap-1.5">
                      <Binary className="w-3.5 h-3.5" />
                      Payload Hex &amp; ASCII Stream View
                    </span>
                    <span className="text-[10px] text-[#94a3b8]">Offset: 0x0000 - 0x00A0</span>
                  </div>

                  {selectedFrame.payload_preview && (
                    <div className="p-2 rounded bg-[#111821] border border-[#1e2a38]">
                      <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Payload ASCII Preview</div>
                      <div className="text-[11px] text-emerald-300 font-mono break-all whitespace-pre-wrap">
                        {selectedFrame.payload_preview}
                      </div>
                    </div>
                  )}

                  <div className="p-2 rounded bg-[#111821] border border-[#1e2a38] max-h-64 overflow-y-auto">
                    <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Hexadecimal Offset Dump</div>
                    <pre className="text-[10px] text-cyan-200 font-mono leading-relaxed whitespace-pre">
                      {selectedFrame.hex_dump || "No raw byte stream available."}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Reconstructed Flows Subview */}
        {activeSubView === "flows" && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 gap-3">
              {dissection?.flows.map((flow) => (
                <div key={flow.flow_id} className="p-3.5 rounded bg-[#0b0f14] border border-[#243244] text-xs space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 font-mono font-bold text-cyan-300">
                      <span>{flow.flow_id}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-[#151e29] border border-[#243244] text-slate-300">
                        {flow.app_layer_proto}
                      </span>
                    </div>

                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-300 border border-red-500/40">
                      {flow.anomaly_flag}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] pt-2 border-t border-[#1e2a38] text-slate-300">
                    <div>
                      <span className="text-[#94a3b8]">Endpoints:</span> {flow.source_endpoint} → {flow.dest_endpoint}
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Packets:</span> {flow.packet_count} ({Math.round(flow.byte_count / 1024)} KB)
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Duration:</span> {flow.duration_ms}ms
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">JA3 Hash:</span> {flow.ja3_fingerprint ? flow.ja3_fingerprint.slice(0, 12) + "..." : "N/A"}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
