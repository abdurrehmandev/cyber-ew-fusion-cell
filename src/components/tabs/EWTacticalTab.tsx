import React, { useState, useEffect } from "react";
import { RFWaterfallCanvas } from "../RFWaterfallCanvas";
import { TacticalRadioAudioDemodulator } from "../TacticalRadioAudioDemodulator";
import {
  Radio,
  Wifi,
  Activity,
  ShieldAlert,
  Sliders,
  Crosshair,
  AlertTriangle,
  Zap,
  Globe,
  Lock,
  RefreshCw,
  Compass,
  CheckCircle2,
  Layers,
  Sparkles,
  Search,
  Filter,
  Eye,
  ChevronRight,
  Gauge,
  Flame,
} from "lucide-react";
import {
  RFEmissionSignal,
  EWThreatVector,
  SpectrumBandMetrics,
  TenantContext,
  AlertRecord,
} from "../../types";

interface EWTacticalTabProps {
  alerts: AlertRecord[];
}

export const EWTacticalTab: React.FC<EWTacticalTabProps> = ({ alerts }) => {
  const [signals, setSignals] = useState<RFEmissionSignal[]>([]);
  const [vectors, setVectors] = useState<EWThreatVector[]>([]);
  const [bands, setBands] = useState<SpectrumBandMetrics[]>([]);
  const [tenant, setTenant] = useState<TenantContext | null>(null);
  const [selectedSignal, setSelectedSignal] = useState<RFEmissionSignal | null>(null);
  const [selectedVector, setSelectedVector] = useState<EWThreatVector | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<"Spectrum" | "Vectors" | "RadarFix" | "RBAC">("Spectrum");
  const [loading, setLoading] = useState<boolean>(true);
  const [interceptModalOpen, setInterceptModalOpen] = useState(false);
  const [countermeasureAction, setCountermeasureAction] = useState<string>("");

  // New Intercept form
  const [newFreq, setNewFreq] = useState("2412.0");
  const [newPower, setNewPower] = useState("-38.5");
  const [newMod, setNewMod] = useState<any>("OFDM");
  const [newProt, setNewProt] = useState<any>("C2 Mesh");
  const [newClass, setNewClass] = useState<any>("Hostile C2 Emitter");
  const [newBearing, setNewBearing] = useState("142");

  const fetchData = async () => {
    try {
      setLoading(true);
      const [sigRes, vecRes, bandRes, tenRes] = await Promise.all([
        fetch("/api/ew/signals").then(r => r.json()),
        fetch("/api/ew/threat-vectors").then(r => r.json()),
        fetch("/api/ew/spectrum-metrics").then(r => r.json()),
        fetch("/api/tenant/context").then(r => r.json()),
      ]);
      setSignals(sigRes || []);
      setVectors(vecRes || []);
      setBands(bandRes || []);
      setTenant(tenRes || null);
      if (sigRes && sigRes.length > 0 && !selectedSignal) {
        setSelectedSignal(sigRes[0]);
      }
      if (vecRes && vecRes.length > 0 && !selectedVector) {
        setSelectedVector(vecRes[0]);
      }
    } catch (e) {
      console.error("Error fetching EW data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleInterceptSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/ew/signals/intercept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          freq_mhz: parseFloat(newFreq),
          power_dbm: parseFloat(newPower),
          modulation: newMod,
          protocol_detected: newProt,
          emitter_classification: newClass,
          bearing_deg: parseFloat(newBearing),
        }),
      }).then(r => r.json());
      if (res.signal) {
        setSignals([res.signal, ...signals]);
        setSelectedSignal(res.signal);
        setInterceptModalOpen(false);
      }
    } catch (err) {
      console.error("Intercept inject failed", err);
    }
  };

  const handleEngageCountermeasure = async (vectorId: string, cm: string) => {
    try {
      const res = await fetch("/api/ew/countermeasures/engage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vector_id: vectorId,
          countermeasure: cm,
        }),
      }).then(r => r.json());
      if (res.vector) {
        setVectors(vectors.map(v => v.vector_id === vectorId ? res.vector : v));
        setSelectedVector(res.vector);
        setCountermeasureAction(`Countermeasure [${cm}] successfully engaged on ${vectorId}`);
        setTimeout(() => setCountermeasureAction(""), 4000);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSwitchRole = async (role: string, classification: string) => {
    try {
      const res = await fetch("/api/tenant/switch-role", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role, classification }),
      }).then(r => r.json());
      if (res.context) {
        setTenant(res.context);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const hostileCount = signals.filter(s => s.emitter_classification?.includes("Hostile")).length;
  const criticalVectorsCount = vectors.filter(v => v.severity === "Critical").length;

  return (
    <div className="space-y-6" id="ew-tactical-tab">
      {/* Header & Subtab Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-100">Tactical EW Spectrum & RF-Cyber Fusion</h2>
              <span className="px-2 py-0.5 text-xs font-mono font-semibold bg-red-950/80 text-red-400 border border-red-800 rounded">
                PHASE 6 DEPLOYED
              </span>
              {tenant && (
                <span className="px-2 py-0.5 text-xs font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-800 rounded">
                  {tenant.security_classification}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Cross-domain electronic warfare telemetry, RF emitter triangulation, and cyber threat vector correlation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setInterceptModalOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors shadow-sm"
          >
            <Zap className="w-3.5 h-3.5" />
            Inject RF Intercept
          </button>
          <button
            onClick={fetchData}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Sync Emitters
          </button>
        </div>
      </div>

      {countermeasureAction && (
        <div className="p-3 bg-emerald-950/60 border border-emerald-700 text-emerald-300 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{countermeasureAction}</span>
        </div>
      )}

      {/* Top Level Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-medium">Active RF Signals</span>
            <Wifi className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{signals.length}</div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-emerald-400 font-semibold">100%</span> SDR sensor array uptime
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-medium">Hostile Emitters</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono">{hostileCount}</div>
          <div className="text-xs text-slate-400 mt-1">
            {hostileCount > 0 ? "Targeted jamming / C2 exfil" : "No active hostile emitters"}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-medium">Fused Threat Vectors</span>
            <Crosshair className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 font-mono">{vectors.length}</div>
          <div className="text-xs text-slate-400 mt-1">
            <span className="text-red-400 font-semibold">{criticalVectorsCount} Critical</span> vectors active
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-medium">Active Operator Role</span>
            <Lock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-purple-300 truncate font-mono mt-1">
            {tenant?.assigned_role || "SOC Analyst"}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            {tenant?.permitted_enclaves.length || 0} Enclaves Authorized
          </div>
        </div>
      </div>

      {/* Sub Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab("Spectrum")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === "Spectrum"
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          }`}
        >
          <Radio className="w-4 h-4" />
          RF Intercepts & Spectrum Waterfall ({signals.length})
        </button>

        <button
          onClick={() => setActiveSubTab("Vectors")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === "Vectors"
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          }`}
        >
          <Crosshair className="w-4 h-4" />
          RF-to-Cyber Correlation Vectors ({vectors.length})
        </button>

        <button
          onClick={() => setActiveSubTab("RadarFix")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === "RadarFix"
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          }`}
        >
          <Compass className="w-4 h-4" />
          Direction Finding & Triangulation
        </button>

        <button
          onClick={() => setActiveSubTab("RBAC")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === "RBAC"
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          }`}
        >
          <Lock className="w-4 h-4" />
          Multi-Tenant RBAC & Air-Gap Enclaves
        </button>
      </div>

      {/* SUBTAB 1: SPECTRUM & EMISSION SIGNALS */}
      {activeSubTab === "Spectrum" && (
        <div className="space-y-6">
          {/* Hardware-Accelerated 60 FPS RF Spectrogram Waterfall */}
          <RFWaterfallCanvas
            centerFreqMHz={selectedSignal ? selectedSignal.freq_mhz : 433.92}
            bandwidthMHz={2.5}
            isJammingActive={bands.some((b) => b.jamming_indicator)}
          />

          {/* Real-Time Tactical Radio Audio Demodulator & DSP Oscilloscope */}
          <TacticalRadioAudioDemodulator selectedSignal={selectedSignal} />


          {/* Spectrum Band Health Overview */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Continuous RF Band Occupancy & Jamming Indicators
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              {bands.map((b) => (
                <div
                  key={b.band_name}
                  className={`p-3 rounded-lg border text-xs ${
                    b.jamming_indicator
                      ? "bg-red-950/40 border-red-800/60"
                      : "bg-slate-800/50 border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between font-bold text-slate-200 mb-1">
                    <span>{b.band_name}</span>
                    {b.jamming_indicator && (
                      <span className="px-1.5 py-0.2 bg-red-900 text-red-300 rounded text-[10px]">JAMMING</span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mb-2">{b.range_mhz}</div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400 text-[10px]">
                      <span>Occupancy</span>
                      <span className="font-mono">{b.occupancy_pct}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${b.occupancy_pct > 75 ? "bg-red-500" : b.occupancy_pct > 50 ? "bg-amber-500" : "bg-cyan-500"}`}
                        style={{ width: `${b.occupancy_pct}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-slate-400 text-[10px] pt-1">
                      <span>Noise Floor</span>
                      <span className="font-mono text-slate-300">{b.noise_floor_dbm} dBm</span>
                    </div>
                    <div className="flex justify-between text-slate-400 text-[10px]">
                      <span>Peak Signal</span>
                      <span className="font-mono text-amber-400">{b.peak_signal_dbm} dBm</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Intercept List and Inspector Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-200">SDR Radio Intercept Stream</span>
                <span className="text-xs text-slate-400 font-mono">{signals.length} Signals Captured</span>
              </div>
              <div className="divide-y divide-slate-800 max-h-[500px] overflow-y-auto">
                {signals.map((sig) => {
                  const isSelected = selectedSignal?.id === sig.id;
                  const isHostile = sig.emitter_classification?.includes("Hostile");
                  return (
                    <div
                      key={sig.id}
                      onClick={() => setSelectedSignal(sig)}
                      className={`p-3 cursor-pointer transition-colors flex items-center justify-between ${
                        isSelected
                          ? "bg-amber-500/10 border-l-4 border-amber-500"
                          : "hover:bg-slate-800/50"
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-slate-200 text-xs">{sig.id}</span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              isHostile
                                ? "bg-red-950 text-red-400 border border-red-800"
                                : sig.emitter_classification?.includes("Friendly")
                                ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                                : "bg-amber-950 text-amber-400 border border-amber-800"
                            }`}
                          >
                            {sig.emitter_classification || "Unknown"}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">{sig.protocol_detected}</span>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                          <span>Freq: <strong className="text-cyan-400">{sig.freq_mhz} MHz</strong></span>
                          <span>Pwr: <strong className="text-slate-200">{sig.power_dbm} dBm</strong></span>
                          <span>Mod: <strong className="text-slate-300">{sig.modulation}</strong></span>
                        </div>
                      </div>

                      <div className="text-right">
                        <div className="text-xs font-mono font-bold text-slate-300">
                          {sig.bearing_deg.toFixed(1)}° True
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">
                          CEP: {sig.geographic_fix.cep_radius_m}m
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Signal Inspector */}
            <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-4">
              {selectedSignal ? (
                <>
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div>
                      <h4 className="text-sm font-bold text-slate-200">{selectedSignal.id} Details</h4>
                      <p className="text-xs text-slate-400 font-mono">{selectedSignal.intercept_station}</p>
                    </div>
                    <span
                      className={`px-2 py-1 rounded text-xs font-bold ${
                        selectedSignal.threat_level === "Critical"
                          ? "bg-red-900/80 text-red-200 border border-red-700"
                          : "bg-amber-900/80 text-amber-200 border border-amber-700"
                      }`}
                    >
                      {selectedSignal.threat_level} Threat
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="p-2.5 bg-slate-800/40 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[10px]">Center Frequency</div>
                      <div className="font-mono text-cyan-400 font-bold text-sm">{selectedSignal.freq_mhz} MHz</div>
                      <div className="text-slate-500 text-[10px]">BW: {selectedSignal.bandwidth_khz} kHz</div>
                    </div>

                    <div className="p-2.5 bg-slate-800/40 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[10px]">Signal Strength & SNR</div>
                      <div className="font-mono text-slate-200 font-bold text-sm">{selectedSignal.power_dbm} dBm</div>
                      <div className="text-slate-400 text-[10px]">SNR: +{selectedSignal.snr_db} dB</div>
                    </div>

                    <div className="p-2.5 bg-slate-800/40 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[10px]">Bearing & Elevation</div>
                      <div className="font-mono text-amber-400 font-bold text-sm">{selectedSignal.bearing_deg}° / {selectedSignal.elevation_deg}°</div>
                      <div className="text-slate-500 text-[10px]">Polar Fix: North-referenced</div>
                    </div>

                    <div className="p-2.5 bg-slate-800/40 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[10px]">Jammer Index Score</div>
                      <div className="font-mono text-red-400 font-bold text-sm">{(selectedSignal.jammer_threat_score * 100).toFixed(0)}%</div>
                      <div className="text-slate-400 text-[10px]">Confidence: {(selectedSignal.signal_confidence * 100).toFixed(0)}%</div>
                    </div>
                  </div>

                  {/* Associated Cyber Entity */}
                  {selectedSignal.associated_cyber_entity && (
                    <div className="p-3 bg-indigo-950/30 border border-indigo-800/60 rounded-lg text-xs space-y-1.5">
                      <div className="font-semibold text-indigo-300 flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5" />
                        Fused Cyber Entity Link
                      </div>
                      {selectedSignal.associated_cyber_entity.ip && (
                        <div className="text-slate-300 font-mono">
                          Target IP: <span className="text-amber-400">{selectedSignal.associated_cyber_entity.ip}</span>
                        </div>
                      )}
                      {selectedSignal.associated_cyber_entity.hostname && (
                        <div className="text-slate-300 font-mono">
                          Host: <span className="text-cyan-400">{selectedSignal.associated_cyber_entity.hostname}</span>
                        </div>
                      )}
                      {selectedSignal.associated_cyber_entity.c2_domain && (
                        <div className="text-slate-300 font-mono">
                          C2 Domain: <span className="text-red-400">{selectedSignal.associated_cyber_entity.c2_domain}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Geolocation Fix Coordinate */}
                  <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700 text-xs space-y-1">
                    <div className="text-slate-400 font-semibold flex items-center gap-1">
                      <Compass className="w-3.5 h-3.5 text-cyan-400" />
                      TDoA / AoA Geolocation Fix
                    </div>
                    <div className="font-mono text-slate-300">
                      Lat: {selectedSignal.geographic_fix.lat.toFixed(4)} | Lon: {selectedSignal.geographic_fix.lon.toFixed(4)}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Elevation: {selectedSignal.geographic_fix.elevation_m}m AMSL | Accuracy Radius (CEP 50%): {selectedSignal.geographic_fix.cep_radius_m}m
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-8 text-center text-slate-500 text-xs">Select a signal to inspect</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: RF-TO-CYBER THREAT VECTORS */}
      {activeSubTab === "Vectors" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-amber-400" />
              Correlated Multi-Domain Attack Vectors
            </h3>
            {vectors.map((vec) => {
              const isSelected = selectedVector?.vector_id === vec.vector_id;
              return (
                <div
                  key={vec.vector_id}
                  onClick={() => setSelectedVector(vec)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all shadow-md ${
                    isSelected
                      ? "bg-slate-800/90 border-amber-500 shadow-amber-500/10"
                      : "bg-slate-900 border-slate-800 hover:bg-slate-850"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-amber-400">{vec.vector_id}</span>
                      <span className="text-sm font-bold text-slate-200">{vec.category}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-bold ${
                        vec.severity === "Critical"
                          ? "bg-red-950 text-red-400 border border-red-800"
                          : "bg-amber-950 text-amber-400 border border-amber-800"
                      }`}
                    >
                      {vec.severity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 mb-3 leading-relaxed">
                    {vec.correlation_hypothesis}
                  </p>

                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono border-t border-slate-800 pt-2">
                    <span>Target: <strong className="text-slate-300">{vec.target_subsystem}</strong></span>
                    <span className="text-emerald-400">{vec.status}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Vector Action & Countermeasure Station */}
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            {selectedVector ? (
              <>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <h4 className="text-sm font-bold text-slate-100">{selectedVector.category} Investigation</h4>
                    <p className="text-xs text-slate-400 font-mono">ID: {selectedVector.vector_id} | Confidence: {(selectedVector.confidence_score * 100).toFixed(0)}%</p>
                  </div>
                  <span className="px-2.5 py-1 bg-indigo-950 text-indigo-300 border border-indigo-800 rounded text-xs font-semibold">
                    {selectedVector.active_countermeasure}
                  </span>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-300">Linked RF Intercept Emitters:</span>
                  <div className="flex flex-wrap gap-2">
                    {selectedVector.emitter_ids.map(id => (
                      <span key={id} className="px-2.5 py-1 bg-slate-800 text-amber-300 border border-slate-700 rounded text-xs font-mono">
                        {id}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-300">Linked Cyber Telemetry Alerts:</span>
                  <div className="flex flex-wrap gap-2">
                    {selectedVector.correlated_alert_ids.length > 0 ? (
                      selectedVector.correlated_alert_ids.map(id => (
                        <span key={id} className="px-2.5 py-1 bg-red-950/80 text-red-300 border border-red-800 rounded text-xs font-mono">
                          {id}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">No persistent SOC alert linked yet (Pre-detection RF Phase)</span>
                    )}
                  </div>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-2">
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    Electronic Countermeasures (ECM) Response Dispatch
                  </div>
                  <p className="text-xs text-slate-400">
                    Select an operational EW countermeasure to mitigate cross-domain physical-to-cyber intrusion:
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                    {[
                      "Directional Electronic Countermeasures (ECM)",
                      "Adaptive Frequency Hopping",
                      "Beamforming Nulling",
                      "RF Port Isolation",
                      "Spectral Mask Filtering",
                    ].map((cm) => (
                      <button
                        key={cm}
                        onClick={() => handleEngageCountermeasure(selectedVector.vector_id, cm)}
                        className={`px-3 py-2 text-xs font-semibold rounded-lg border text-left transition-all ${
                          selectedVector.active_countermeasure === cm
                            ? "bg-emerald-950 text-emerald-300 border-emerald-600 shadow-sm"
                            : "bg-slate-800/80 text-slate-300 border-slate-700 hover:bg-slate-700"
                        }`}
                      >
                        {cm}
                      </button>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs">Select a threat vector to inspect</div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 3: DIRECTION FINDING & RADAR TRIANGULATION CANVAS */}
      {activeSubTab === "RadarFix" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Compass className="w-5 h-5 text-amber-400 animate-spin" style={{ animationDuration: "12s" }} />
                <h3 className="text-sm font-semibold text-slate-100">Tactical 360° Angle-of-Arrival (AoA) Radar Scope</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">Sensors: 4 Ground Array SDRs</span>
            </div>

            {/* Visual Polar Scope Simulation */}
            <div className="relative w-full aspect-square max-w-[420px] mx-auto bg-slate-950 border-2 border-slate-800 rounded-full flex items-center justify-center overflow-hidden shadow-inner">
              {/* Concentric distance rings */}
              <div className="absolute inset-4 border border-slate-800/80 rounded-full" />
              <div className="absolute inset-16 border border-slate-800/80 rounded-full" />
              <div className="absolute inset-28 border border-slate-800/80 rounded-full" />
              <div className="absolute inset-40 border border-slate-800/80 rounded-full" />

              {/* Crosshairs */}
              <div className="absolute w-full h-[1px] bg-slate-800" />
              <div className="absolute h-full w-[1px] bg-slate-800" />

              {/* Angle Labels */}
              <span className="absolute top-2 text-[10px] font-mono text-slate-500 font-bold">000° N</span>
              <span className="absolute bottom-2 text-[10px] font-mono text-slate-500 font-bold">180° S</span>
              <span className="absolute left-2 text-[10px] font-mono text-slate-500 font-bold">270° W</span>
              <span className="absolute right-2 text-[10px] font-mono text-slate-500 font-bold">090° E</span>

              {/* Center station */}
              <div className="w-3 h-3 bg-cyan-400 rounded-full z-10 shadow-[0_0_12px_#22d3ee]" />

              {/* Signal points mapped around polar plane */}
              {signals.map((sig) => {
                const rad = (sig.bearing_deg - 90) * (Math.PI / 180);
                const distancePct = Math.min(42, Math.max(12, (sig.geographic_fix.cep_radius_m / 150) * 40));
                const x = Math.cos(rad) * distancePct;
                const y = Math.sin(rad) * distancePct;
                const isHostile = sig.emitter_classification?.includes("Hostile");

                return (
                  <div
                    key={sig.id}
                    onClick={() => setSelectedSignal(sig)}
                    style={{
                      transform: `translate(${x * 3.8}px, ${y * 3.8}px)`,
                    }}
                    className={`absolute cursor-pointer p-1 rounded-full group transition-all z-20 ${
                      selectedSignal?.id === sig.id ? "scale-125" : "hover:scale-110"
                    }`}
                  >
                    <div
                      className={`w-3.5 h-3.5 rounded-full border-2 ${
                        isHostile
                          ? "bg-red-500 border-red-300 shadow-[0_0_10px_#ef4444]"
                          : sig.emitter_classification?.includes("Friendly")
                          ? "bg-emerald-500 border-emerald-300 shadow-[0_0_8px_#10b981]"
                          : "bg-amber-500 border-amber-300 shadow-[0_0_8px_#f59e0b]"
                      }`}
                    />
                    <span className="absolute bottom-5 left-1/2 -translate-x-1/2 px-1.5 py-0.5 bg-slate-900 border border-slate-700 text-slate-200 text-[9px] font-mono rounded opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap z-30">
                      {sig.id} ({sig.bearing_deg.toFixed(0)}°)
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h4 className="text-sm font-semibold text-slate-200">Sensor Triangulation Matrix</h4>
            <p className="text-xs text-slate-400">
              Correlated Time-Difference-of-Arrival (TDoA) and Angle-of-Arrival (AoA) geometry computed across tactical SDR receivers.
            </p>

            <div className="space-y-3">
              {[
                { station: "SIGINT-STATION-ALPHA", mast: "Perimeter Mast 04", status: "Nominal", freq_range: "20 MHz - 6 GHz" },
                { station: "SIGINT-STATION-BRAVO", mast: "Airfield Sensor 02", status: "Nominal", freq_range: "100 MHz - 3 GHz" },
                { station: "SIGINT-STATION-CHARLIE", mast: "Roof Tactical Array", status: "Nominal", freq_range: "400 MHz - 8 GHz" },
                { station: "SIGINT-STATION-DELTA", mast: "Mobile SDR Unit 01", status: "Calibrated", freq_range: "1 MHz - 6 GHz" },
              ].map((st) => (
                <div key={st.station} className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 text-xs flex items-center justify-between">
                  <div>
                    <div className="font-bold text-slate-200 font-mono">{st.station}</div>
                    <div className="text-slate-400 text-[11px]">{st.mast}</div>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded text-[10px] font-semibold">
                      {st.status}
                    </span>
                    <div className="text-[10px] text-slate-500 font-mono mt-1">{st.freq_range}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 4: MULTI-TENANT RBAC & ENCLAVES */}
      {activeSubTab === "RBAC" && tenant && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" />
                Air-Gapped Multi-Tenant RBAC Policy
              </h3>
              <span className="px-2 py-0.5 bg-purple-950 text-purple-300 border border-purple-800 rounded text-xs font-mono font-bold">
                {tenant.tenant_id}
              </span>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="text-slate-400 text-[10px]">Active Command Enclave Name</div>
                <div className="font-bold text-slate-200 text-sm mt-0.5">{tenant.name}</div>
              </div>

              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="text-slate-400 text-[10px]">Assigned Authorization Role</div>
                <div className="font-bold text-purple-300 text-sm mt-0.5">{tenant.assigned_role}</div>
              </div>

              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="text-slate-400 text-[10px]">Permitted Air-Gapped Network Enclaves</div>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {tenant.permitted_enclaves.map((enc) => (
                    <span key={enc} className="px-2 py-0.5 bg-slate-900 text-slate-300 border border-slate-700 rounded text-[11px] font-mono">
                      {enc}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="text-slate-400 text-[10px]">Session Crypto Token (HMAC-SHA256)</div>
                <div className="font-mono text-emerald-400 text-xs mt-0.5 break-all">
                  {tenant.active_session_token}
                </div>
              </div>
            </div>
          </div>

          {/* Role Switching Simulator */}
          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Role Privilege & Enclave Escalation Simulation
            </h3>
            <p className="text-xs text-slate-400">
              Simulate operational role transitions to verify strict tenant isolation and air-gapped access barriers:
            </p>

            <div className="space-y-2 pt-2">
              {[
                { role: "Global SOC Director", classif: "TOP SECRET // NOFORN", desc: "Unrestricted visibility across all EW RF and cyber network domains." },
                { role: "Senior Tier-3 Hunter", classif: "SECRET", desc: "Full query engine & threat vector containment execution rights." },
                { role: "EW Specialist Operator", classif: "TOP SECRET // NOFORN", desc: "Dedicated access to tactical RF directional radar, jamming indices, and SDR streams." },
                { role: "SOC Analyst", classif: "CONFIDENTIAL", desc: "Alert triage, investigation tagging, and ticket workflow assignment." },
                { role: "Auditor / Read-Only", classif: "UNCLASSIFIED", desc: "Compliance verification with all mutation actions and playbooks locked." },
              ].map((r) => (
                <div
                  key={r.role}
                  onClick={() => handleSwitchRole(r.role, r.classif)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    tenant.assigned_role === r.role
                      ? "bg-purple-950/40 border-purple-500 shadow-sm"
                      : "bg-slate-800/40 border-slate-800 hover:bg-slate-800/80"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-slate-200">{r.role}</span>
                    <span className="text-[10px] font-mono font-semibold px-2 py-0.5 bg-slate-900 border border-slate-700 text-purple-300 rounded">
                      {r.classif}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">{r.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: INJECT RF INTERCEPT */}
      {interceptModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold text-slate-100">Inject Tactical RF Intercept Telemetry</h3>
              </div>
              <button
                onClick={() => setInterceptModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleInterceptSubmit} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Center Frequency (MHz)</label>
                  <input
                    type="number"
                    step="0.01"
                    value={newFreq}
                    onChange={(e) => setNewFreq(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100 font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Signal Power (dBm)</label>
                  <input
                    type="number"
                    step="0.1"
                    value={newPower}
                    onChange={(e) => setNewPower(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100 font-mono"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Modulation</label>
                  <select
                    value={newMod}
                    onChange={(e) => setNewMod(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100"
                  >
                    <option value="OFDM">OFDM</option>
                    <option value="QAM">QAM</option>
                    <option value="FSK">FSK</option>
                    <option value="DSSS">DSSS</option>
                    <option value="FHSS">FHSS</option>
                    <option value="Chirp">Chirp</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Detected Protocol</label>
                  <select
                    value={newProt}
                    onChange={(e) => setNewProt(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100"
                  >
                    <option value="C2 Mesh">C2 Mesh</option>
                    <option value="GPS Spoofing">GPS Spoofing</option>
                    <option value="UAV Telemetry">UAV Telemetry</option>
                    <option value="Tactical Data Link">Tactical Data Link</option>
                    <option value="Rogue Wi-Fi/BLE">Rogue Wi-Fi/BLE</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Emitter Classification</label>
                  <select
                    value={newClass}
                    onChange={(e) => setNewClass(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100"
                  >
                    <option value="Hostile C2 Emitter">Hostile C2 Emitter</option>
                    <option value="Hostile Jammer">Hostile Jammer</option>
                    <option value="Suspect Transponder">Suspect Transponder</option>
                    <option value="Friendly Beacon">Friendly Beacon</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">AoA Bearing (° True)</label>
                  <input
                    type="number"
                    step="1"
                    min="0"
                    max="359"
                    value={newBearing}
                    onChange={(e) => setNewBearing(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-slate-100 font-mono"
                    required
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setInterceptModalOpen(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold rounded"
                >
                  Transmit & Ingest Signal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
