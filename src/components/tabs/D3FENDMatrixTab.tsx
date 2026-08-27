import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  CheckCircle2,
  Lock,
  Layers,
  Zap,
  Eye,
  Radio,
  Workflow,
  Crosshair,
  Sparkles,
  RefreshCw,
} from "lucide-react";
import { D3FENDMatrixOverview, D3FENDCountermeasure, D3FENDPillar } from "../../types";

export const D3FENDMatrixTab: React.FC = () => {
  const [matrix, setMatrix] = useState<D3FENDMatrixOverview | null>(null);
  const [selectedPillar, setSelectedPillar] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedCountermeasure, setSelectedCountermeasure] = useState<D3FENDCountermeasure | null>(null);
  const [isVerifying, setIsVerifying] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<string | null>(null);

  const fetchMatrix = async () => {
    try {
      const res = await fetch("/api/d3fend/matrix");
      const data: D3FENDMatrixOverview = await res.json();
      setMatrix(data);
      if (!selectedCountermeasure && data.pillars.length > 0 && data.pillars[0].countermeasures.length > 0) {
        setSelectedCountermeasure(data.pillars[0].countermeasures[0]);
      }
    } catch (err) {
      console.error("Error fetching D3FEND matrix:", err);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, []);

  const handleVerify = async (d3fendId: string) => {
    setIsVerifying(d3fendId);
    try {
      const res = await fetch("/api/d3fend/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ d3fend_id: d3fendId }),
      });
      const data = await res.json();
      if (data.countermeasure) {
        setSelectedCountermeasure(data.countermeasure);
        setVerificationFeedback(`Verified ${d3fendId}: Synthetic adversary test succeeded! Confidence increased.`);
        fetchMatrix();
        setTimeout(() => setVerificationFeedback(null), 3500);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsVerifying(null);
    }
  };

  const allCountermeasures = matrix?.pillars.flatMap((p) => p.countermeasures) || [];

  const filteredCountermeasures = allCountermeasures.filter((item) => {
    if (!item) return false;
    if (selectedPillar !== "ALL" && item.pillar !== selectedPillar) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (item.d3fend_id || "").toLowerCase().includes(q) ||
      (item.d3fend_name || "").toLowerCase().includes(q) ||
      (item.description || "").toLowerCase().includes(q) ||
      (item.mitre_attack_countered || []).some((a) =>
        (a?.technique_id || "").toLowerCase().includes(q) ||
        (a?.technique_name || "").toLowerCase().includes(q)
      )
    );
  });

  const getPillarColor = (pillar: D3FENDPillar) => {
    switch (pillar) {
      case "Model":
        return "text-blue-400 border-blue-500/40 bg-blue-500/10";
      case "Harden":
        return "text-emerald-400 border-emerald-500/40 bg-emerald-500/10";
      case "Detect":
        return "text-cyan-400 border-cyan-500/40 bg-cyan-500/10";
      case "Isolate":
        return "text-purple-400 border-purple-500/40 bg-purple-500/10";
      case "Deceive":
        return "text-amber-400 border-amber-500/40 bg-amber-500/10";
      case "Evict":
        return "text-red-400 border-red-500/40 bg-red-500/10";
      default:
        return "text-slate-400 border-slate-500/40 bg-slate-500/10";
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header Card */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[#e8edf2] flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            MITRE D3FEND™ Defensive Countermeasure Matrix Mapping
          </h2>
          <p className="text-xs text-[#94a3b8]">
            Knowledge graph mapping active defensive cyber &amp; EW countermeasures against MITRE ATT&amp;CK® adversary techniques
          </p>
        </div>

        {matrix && (
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-xs text-[#94a3b8]">Defensive Coverage</div>
              <div className="text-base font-bold text-emerald-400">
                {matrix.coverage_percentage}% Enforced ({matrix.active_enforced_count}/{matrix.total_countermeasures})
              </div>
            </div>
          </div>
        )}
      </div>

      {verificationFeedback && (
        <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{verificationFeedback}</span>
        </div>
      )}

      {/* 6-Pillar Summary Bar */}
      {matrix && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 text-xs">
          {matrix.pillars.map((p) => {
            const count = p.countermeasures.length;
            const isSelected = selectedPillar === p.pillar;
            return (
              <button
                key={p.pillar}
                onClick={() => setSelectedPillar(selectedPillar === p.pillar ? "ALL" : p.pillar)}
                className={`p-3 rounded-lg border text-left transition-all ${
                  isSelected
                    ? "bg-cyan-500/20 border-cyan-400 text-cyan-200 shadow-md"
                    : "bg-[#111821] border-[#243244] text-[#cbd5e1] hover:bg-[#151e29]"
                }`}
              >
                <div className="text-[10px] uppercase font-mono text-[#94a3b8] mb-0.5">Pillar</div>
                <div className="font-bold text-sm text-[#e8edf2]">{p.pillar}</div>
                <div className="text-[11px] text-[#94a3b8] mt-1">{count} Countermeasures</div>
              </button>
            );
          })}
        </div>
      )}

      {/* Filters & Search */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 p-3 rounded-lg bg-[#111821] border border-[#243244]">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-[11px] text-[#94a3b8] mr-1">Filter Pillar:</span>
          {["ALL", "Model", "Harden", "Detect", "Isolate", "Deceive", "Evict"].map((pill) => (
            <button
              key={pill}
              onClick={() => setSelectedPillar(pill)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors border ${
                selectedPillar === pill
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                  : "bg-[#151e29] text-[#94a3b8] border-[#243244] hover:text-[#e8edf2]"
              }`}
            >
              {pill}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#94a3b8]" />
          <input
            type="text"
            placeholder="Search D3FEND / ATT&CK..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1 text-xs bg-[#0b0f14] text-[#e8edf2] rounded border border-[#243244] focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Matrix Grid & Deep Details Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Countermeasures List (2 Cols) */}
        <div className="lg:col-span-2 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {filteredCountermeasures.map((item) => {
              const isSelected = selectedCountermeasure?.d3fend_id === item.d3fend_id;
              return (
                <div
                  key={item.d3fend_id}
                  onClick={() => setSelectedCountermeasure(item)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                    isSelected
                      ? "bg-[#151e29] border-cyan-400 shadow-md ring-1 ring-cyan-400/40"
                      : "bg-[#111821] border-[#243244] hover:bg-[#151e29]/70"
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPillarColor(item.pillar)}`}>
                        {item.pillar}: {item.d3fend_id}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#0b0f14] text-emerald-400 font-mono">
                        {item.confidence_pct}% Conf
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-[#e8edf2] mb-1 leading-snug">{item.d3fend_name}</h4>
                    <p className="text-[11px] text-[#94a3b8] line-clamp-2 mb-2">{item.description}</p>
                  </div>

                  <div className="pt-2 border-t border-[#1e2a38] space-y-1.5">
                    <div className="text-[10px] text-[#94a3b8]">Counters ATT&amp;CK:</div>
                    <div className="flex flex-wrap gap-1">
                      {item.mitre_attack_countered.map((att) => (
                        <span
                          key={att.technique_id}
                          className="px-1.5 py-0.5 rounded bg-[#0b0f14] border border-[#243244] text-[10px] font-mono text-cyan-300"
                        >
                          {att.technique_id}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Countermeasure Detailed Verification Card (1 Col) */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#1e2a38]">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#e8edf2]">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Countermeasure Inspector</span>
            </div>
            {selectedCountermeasure && (
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#151e29] text-emerald-300 border border-[#243244]">
                {selectedCountermeasure.operational_status}
              </span>
            )}
          </div>

          {selectedCountermeasure ? (
            <div className="space-y-3.5 text-xs">
              <div>
                <div className="text-sm font-semibold text-cyan-300 mb-1">{selectedCountermeasure.d3fend_name}</div>
                <div className="text-[11px] text-[#94a3b8] font-mono mb-2">ID: {selectedCountermeasure.d3fend_id} | Pillar: {selectedCountermeasure.pillar}</div>
                <p className="text-xs text-[#cbd5e1] leading-relaxed bg-[#0b0f14] p-2.5 rounded border border-[#243244]">
                  {selectedCountermeasure.description}
                </p>
              </div>

              {/* Defensive Artifact */}
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244]">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono mb-1">Defensive Artifact &amp; Engine</div>
                <div className="text-xs font-mono text-emerald-300">{selectedCountermeasure.defensive_artifact}</div>
              </div>

              {/* Countered MITRE ATT&CK Techniques */}
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244] space-y-1.5">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono">MITRE ATT&amp;CK Adversary Vectors Neutralized</div>
                <div className="space-y-1">
                  {selectedCountermeasure.mitre_attack_countered.map((att) => (
                    <div key={att.technique_id} className="flex items-center justify-between text-[11px] text-[#cbd5e1]">
                      <span className="font-mono text-cyan-300 font-bold">{att.technique_id}</span>
                      <span className="text-right text-[#94a3b8] truncate max-w-[170px]">{att.technique_name}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Synthetic Verification Test */}
              <div className="p-2.5 rounded bg-[#0b0f14] border border-[#243244] space-y-2">
                <div className="text-[10px] text-[#94a3b8] uppercase font-mono">Automated Verification Test Protocol</div>
                <div className="text-[11px] text-slate-300 leading-normal">
                  {selectedCountermeasure.verification_test}
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-[#1e2a38] text-[10px] text-[#94a3b8]">
                  <span>Last Verified: {new Date(selectedCountermeasure.last_verified_at).toLocaleTimeString()}</span>
                  <span className="text-emerald-400 font-bold">{selectedCountermeasure.confidence_pct}% Confidence</span>
                </div>
              </div>

              <button
                onClick={() => handleVerify(selectedCountermeasure.d3fend_id)}
                disabled={isVerifying === selectedCountermeasure.d3fend_id}
                className="w-full py-2 px-3 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-md transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isVerifying === selectedCountermeasure.d3fend_id ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Injecting Synthetic Vector &amp; Verifying...
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    Run Countermeasure Verification
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-[#94a3b8]">
              Select a defensive countermeasure card from the matrix to inspect its validation telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
