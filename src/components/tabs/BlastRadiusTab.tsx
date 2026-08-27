import React, { useState, useEffect, useRef } from "react";
import * as d3 from "d3";
import {
  GitFork,
  Play,
  SkipForward,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  DollarSign,
  AlertTriangle,
  Server,
  Layers,
  Flame,
  Radio,
  Lock
} from "lucide-react";
import { BlastRadiusState, BlastRadiusNode, BlastRadiusEdge } from "../../types";

export const BlastRadiusTab: React.FC = () => {
  const [state, setState] = useState<BlastRadiusState | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("WS-FIN-09");
  const [patientZeroId, setPatientZeroId] = useState<string>("WS-FIN-09");
  const [loading, setLoading] = useState(false);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const simulationRef = useRef<d3.Simulation<any, any> | null>(null);

  const fetchState = async () => {
    try {
      const res = await fetch("/api/blast-radius/state");
      if (res.ok) {
        const data = await res.json();
        setState(data);
      }
    } catch (err) {
      console.error("Error fetching blast radius state:", err);
    }
  };

  useEffect(() => {
    fetchState();
  }, []);

  const handleSetPatientZero = async (pZero: string) => {
    setPatientZeroId(pZero);
    setLoading(true);
    try {
      const res = await fetch("/api/blast-radius/patient-zero", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ patient_zero_id: pZero })
      });
      if (res.ok) {
        const data = await res.json();
        setState(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleStepSimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/blast-radius/step", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setState(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleQuarantineNode = async (nodeId: string) => {
    setLoading(true);
    try {
      const res = await fetch("/api/blast-radius/quarantine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_id: nodeId })
      });
      if (res.ok) {
        const data = await res.json();
        setState(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleResetSimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/blast-radius/reset", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setState(data);
        setPatientZeroId("WS-FIN-09");
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // D3 Force Graph Setup & Animation
  useEffect(() => {
    if (!state || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 800;
    const height = 480;

    const g = svg.append("g");

    // Add zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 3])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    svg.call(zoom);

    // Deep clone nodes and edges for d3 mutation
    const nodes = state.nodes.map(d => ({ ...d }));
    const edges = state.edges.map(d => ({
      ...d,
      source: typeof d.source === "string" ? d.source : (d.source as any).id,
      target: typeof d.target === "string" ? d.target : (d.target as any).id
    }));

    const simulation = d3.forceSimulation(nodes as any)
      .force("link", d3.forceLink(edges as any).id((d: any) => d.id).distance(110))
      .force("charge", d3.forceManyBody().strength(-380))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(40));

    simulationRef.current = simulation;

    // Arrow markers
    svg.append("defs").selectAll("marker")
      .data(["normal", "infected", "blocked"])
      .enter().append("marker")
      .attr("id", d => `arrow-${d}`)
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 26)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", d => d === "infected" ? "#ef4444" : d === "blocked" ? "#64748b" : "#3b82f6");

    // Draw Links
    const link = g.append("g")
      .selectAll("line")
      .data(edges)
      .enter().append("line")
      .attr("stroke", (d: any) => d.blocked_by_d3fend ? "#475569" : d.is_compromised_path ? "#ef4444" : "#1e3a8a")
      .attr("stroke-width", (d: any) => d.is_compromised_path ? 3 : 1.5)
      .attr("stroke-dasharray", (d: any) => d.blocked_by_d3fend ? "4 4" : "none")
      .attr("marker-end", (d: any) => d.blocked_by_d3fend ? "url(#arrow-blocked)" : d.is_compromised_path ? "url(#arrow-infected)" : "url(#arrow-normal)");

    // Link Labels (Protocols)
    const linkText = g.append("g")
      .selectAll("text")
      .data(edges)
      .enter().append("text")
      .attr("font-family", "monospace")
      .attr("font-size", "8px")
      .attr("fill", "#64748b")
      .attr("text-anchor", "middle")
      .text((d: any) => d.protocol);

    // Draw Nodes
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .enter().append("g")
      .attr("cursor", "pointer")
      .call(
        d3.drag<any, any>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on("click", (event, d: any) => {
        setSelectedNodeId(d.id);
      });

    // Node outer pulsing circle for infected
    node.append("circle")
      .attr("r", 24)
      .attr("fill", (d: any) =>
        d.status === "Patient Zero" ? "rgba(239, 68, 68, 0.3)" :
        d.status === "Infected" ? "rgba(249, 115, 22, 0.25)" :
        d.status === "Quarantined" ? "rgba(100, 116, 139, 0.2)" : "rgba(16, 185, 129, 0.15)"
      )
      .attr("stroke", (d: any) =>
        d.status === "Patient Zero" ? "#ef4444" :
        d.status === "Infected" ? "#f97316" :
        d.status === "Quarantined" ? "#64748b" : "#10b981"
      )
      .attr("stroke-width", 2);

    // Node inner core
    node.append("circle")
      .attr("r", 14)
      .attr("fill", (d: any) =>
        d.status === "Patient Zero" ? "#ef4444" :
        d.status === "Infected" ? "#f97316" :
        d.status === "Quarantined" ? "#334155" : "#0f172a"
      )
      .attr("stroke", "#ffffff")
      .attr("stroke-width", 1);

    // Node Labels
    node.append("text")
      .attr("dy", 36)
      .attr("text-anchor", "middle")
      .attr("font-family", "monospace")
      .attr("font-size", "10px")
      .attr("font-weight", "bold")
      .attr("fill", (d: any) =>
        d.status === "Patient Zero" || d.status === "Infected" ? "#fca5a5" :
        d.status === "Quarantined" ? "#94a3b8" : "#cbd5e1"
      )
      .text((d: any) => d.id);

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      linkText
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2 - 4);

      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [state]);

  const selectedNode = state?.nodes.find(n => n.id === selectedNodeId);

  return (
    <div id="blast-radius-physics-engine" className="space-y-6">
      {/* Top Controller Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-red-500/10 text-red-400 border border-red-500/30">
            <GitFork className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-slate-100">
                Interactive Attack Graph Physics & Blast-Radius Engine
              </h2>
              <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                Step: {state?.simulation_step ?? 0}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              D3 force-directed physics engine modeling live contagion spread across Active Directory, OT/SCADA switchgear, and Cloud IAM.
            </p>
          </div>
        </div>

        {/* Simulation Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={patientZeroId}
            onChange={(e) => handleSetPatientZero(e.target.value)}
            disabled={loading}
            className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500 cursor-pointer"
          >
            {state?.nodes.map(n => (
              <option key={n.id} value={n.id}>Patient Zero: {n.id}</option>
            ))}
          </select>

          <button
            onClick={handleStepSimulation}
            disabled={loading || !state?.is_propagating}
            className="px-3 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 shadow-lg shadow-red-600/20 cursor-pointer"
          >
            <SkipForward className="w-3.5 h-3.5" />
            Step Contagion
          </button>

          <button
            onClick={handleResetSimulation}
            disabled={loading}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono flex items-center gap-1.5 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            Reset Topology
          </button>
        </div>
      </div>

      {/* Blast Impact KPI Bar */}
      {state && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span className="text-[10px] font-mono text-slate-400 block">TOTAL FINANCIAL LOSS</span>
            <span className="text-xl font-bold font-mono text-red-400">
              ${(state.total_loss_usd / 1000000).toFixed(2)}M
            </span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span className="text-[10px] font-mono text-slate-400 block">GRID LOAD SHED</span>
            <span className="text-xl font-bold font-mono text-amber-400">
              {state.total_mw_lost.toFixed(1)} MW
            </span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span className="text-[10px] font-mono text-slate-400 block">COMPROMISED NODES</span>
            <span className="text-xl font-bold font-mono text-red-400">
              {state.compromised_nodes_count} / {state.nodes.length}
            </span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span className="text-[10px] font-mono text-slate-400 block">QUARANTINED (ISOLATED)</span>
            <span className="text-xl font-bold font-mono text-emerald-400">
              {state.quarantined_nodes_count} Nodes
            </span>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <span className="text-[10px] font-mono text-slate-400 block">CONTAGION STATUS</span>
            <span className={`text-sm font-bold font-mono ${state.is_propagating ? "text-red-400 animate-pulse" : "text-emerald-400"}`}>
              {state.is_propagating ? "PROPAGATING // ACTIVE" : "CONTAINED / HALTED"}
            </span>
          </div>
        </div>
      )}

      {/* Main Physics Graph & Inspector Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive D3 Graph Canvas */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden relative shadow-inner">
          <div className="absolute top-3 left-3 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg text-[10px] font-mono text-slate-300 z-10 flex items-center gap-3">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500"></span> Infected / Patient Zero</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500"></span> Clean</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-500"></span> Quarantined</span>
          </div>

          <svg
            ref={svgRef}
            viewBox="0 0 800 480"
            className="w-full h-[480px] block"
          />
        </div>

        {/* Right Col: Node Inspector & Quarantine Action */}
        <div className="space-y-4">
          {selectedNode ? (
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-100">{selectedNode.label}</h3>
                  <span className="text-xs font-mono text-cyan-400">{selectedNode.zone}</span>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                  selectedNode.status === "Patient Zero" || selectedNode.status === "Infected"
                    ? "bg-red-500/20 text-red-400 border border-red-500/40"
                    : selectedNode.status === "Quarantined"
                    ? "bg-slate-800 text-slate-400 border border-slate-700"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                }`}>
                  {selectedNode.status}
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Node Criticality:</span>
                  <span className="text-amber-400 font-bold">{selectedNode.criticality}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">IP Address:</span>
                  <span className="text-slate-200">{selectedNode.ip || "N/A"}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Asset Value:</span>
                  <span className="text-emerald-400 font-bold">${selectedNode.financial_value_usd.toLocaleString()}</span>
                </div>
                {selectedNode.power_draw_mw ? (
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Power Impact:</span>
                    <span className="text-cyan-400 font-bold">{selectedNode.power_draw_mw} MW</span>
                  </div>
                ) : null}
                <div className="py-1">
                  <span className="text-slate-400 block mb-1">Known Exploitable Vector:</span>
                  <p className="text-[11px] text-red-300 bg-red-950/40 p-2 rounded border border-red-900/60 font-sans">
                    {selectedNode.vulnerability || "None identified."}
                  </p>
                </div>
              </div>

              {/* Quarantine Action */}
              <div className="pt-2 border-t border-slate-800">
                <button
                  onClick={() => handleQuarantineNode(selectedNode.id)}
                  disabled={selectedNode.status === "Quarantined"}
                  className={`w-full py-2.5 rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-2 cursor-pointer transition-all ${
                    selectedNode.status === "Quarantined"
                      ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                      : "bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20"
                  }`}
                >
                  <Lock className="w-3.5 h-3.5" />
                  {selectedNode.status === "Quarantined" ? "Node Quarantined (Zero-Trust)" : "Enforce D3FEND Quarantine"}
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 p-8 rounded-xl text-center text-slate-400 text-xs font-mono">
              Click any graph node to inspect blast metrics & quarantine.
            </div>
          )}

          {/* Propagation Step Ledger */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
            <h4 className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
              <Flame className="w-3.5 h-3.5 text-red-400" />
              Contagion Telemetry Ledger
            </h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto text-[11px] font-mono">
              {state?.propagation_log.map((log, idx) => (
                <div key={idx} className="p-2 rounded bg-slate-950 border border-slate-800/80 space-y-0.5">
                  <div className="flex justify-between text-slate-400 text-[10px]">
                    <span>Step {log.step} // {log.protocol}</span>
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-slate-200">{log.vector}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
