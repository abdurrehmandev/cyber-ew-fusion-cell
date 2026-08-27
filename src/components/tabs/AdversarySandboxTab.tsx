import React, { useEffect, useState } from "react";
import {
  AdversaryScenario,
  SimulationState,
  SimulationStep
} from "../../types";
import {
  Play,
  FastForward,
  RotateCcw,
  ShieldAlert,
  Flame,
  Radio,
  Globe,
  Binary,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Terminal,
  Activity,
  ArrowRight,
  ShieldCheck,
  Lock
} from "lucide-react";

export const AdversarySandboxTab: React.FC = () => {
  const [scenarios, setScenarios] = useState<AdversaryScenario[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("scen-sandworm-scada");
  const [simState, setSimState] = useState<SimulationState | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStepTab, setActiveStepTab] = useState<number>(1);

  // Fetch scenarios & state
  const fetchScenarios = async () => {
    try {
      const res = await fetch("/api/simulation/scenarios");
      const data = await res.json();
      setScenarios(data);
    } catch (err) {
      console.error("Failed to load simulation scenarios", err);
    }
  };

  const fetchState = async () => {
    try {
      const res = await fetch("/api/simulation/state");
      const data = await res.json();
      setSimState(data);
    } catch (err) {
      console.error("Failed to load simulation state", err);
    }
  };

  useEffect(() => {
    fetchScenarios();
    fetchState();
    const interval = setInterval(fetchState, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async (scenarioId: string) => {
    setLoading(true);
    try {
      const res = await fetch("/api/simulation/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenarioId })
      });
      const data = await res.json();
      setSimState(data.state);
      fetchScenarios();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleStep = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/simulation/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      setSimState(data.state);
      fetchScenarios();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleBurst = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/simulation/burst", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      setSimState(data.state);
      fetchScenarios();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/simulation/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      setSimState(data.state);
      fetchScenarios();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const currentScenario = scenarios.find((s) => s.id === selectedScenarioId) || scenarios[0];
  const isRunningThisScenario = simState?.active_scenario_id === currentScenario?.id;

  const getDomainIcon = (domain: string) => {
    switch (domain) {
      case "RF / Electronic Warfare":
        return <Radio className="w-4 h-4 text-amber-400" />;
      case "Physical / GIS":
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case "Network / DPI":
        return <Binary className="w-4 h-4 text-indigo-400" />;
      default:
        return <Flame className="w-4 h-4 text-rose-400" />;
    }
  };

  return (
    <div id="adversary-sandbox-tab" className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-100 tracking-wide">
                Adversary Simulation Sandbox & Red-Team Injector
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                ACTIVE TESTBED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Execute controlled multi-domain adversary campaigns into the live detection engine to validate D3FEND rules, GIS bearings, and PCAP dissection.
            </p>
          </div>
        </div>

        {/* Global Live Simulation Controls */}
        <div className="flex items-center gap-2">
          {isRunningThisScenario ? (
            <>
              <button
                id="sandbox-step-btn"
                onClick={handleStep}
                disabled={loading || simState?.status === "Completed"}
                className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-indigo-600/20 transition-all cursor-pointer"
              >
                <ArrowRight className="w-4 h-4" />
                Inject Next Stage ({simState?.current_step_index || 0}/{simState?.total_steps || 0})
              </button>
              <button
                id="sandbox-burst-btn"
                onClick={handleBurst}
                disabled={loading || simState?.status === "Completed"}
                className="px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-amber-600/20 transition-all cursor-pointer"
              >
                <FastForward className="w-4 h-4" />
                Burst Full Attack
              </button>
            </>
          ) : (
            <button
              id="sandbox-start-btn"
              onClick={() => handleStart(currentScenario.id)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all cursor-pointer"
            >
              <Play className="w-4 h-4" />
              Arm & Launch Scenario
            </button>
          )}

          <button
            id="sandbox-reset-btn"
            onClick={handleReset}
            disabled={loading}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-all cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset State
          </button>
        </div>
      </div>

      {/* Live Simulation Status Counters */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Simulation Status</div>
            <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
              {simState?.status || "Idle"}
              {simState?.status === "Running" && (
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Telemetry Generated</div>
            <div className="text-base font-bold text-slate-100">
              {simState?.events_generated || 0} <span className="text-xs font-normal text-slate-400">events</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">Alerts Injected</div>
            <div className="text-base font-bold text-slate-100">
              {simState?.alerts_fired || 0} <span className="text-xs font-normal text-slate-400">alerts</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-slate-400">D3FEND Blocks</div>
            <div className="text-base font-bold text-indigo-300">
              {simState?.d3fend_blocks_triggered || 0} <span className="text-xs font-normal text-slate-400">countermeasures</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Scenario List Selector */}
        <div className="lg:col-span-4 space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">
            Threat Actor Campaign Presets
          </div>

          <div className="space-y-2">
            {scenarios.map((scen) => {
              const isSelected = scen.id === selectedScenarioId;
              const isActiveInSim = simState?.active_scenario_id === scen.id;

              return (
                <div
                  key={scen.id}
                  id={`scenario-card-${scen.id}`}
                  onClick={() => setSelectedScenarioId(scen.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col gap-2 ${
                    isSelected
                      ? "bg-slate-800/90 border-red-500/60 shadow-lg shadow-red-950/20"
                      : "bg-slate-900/70 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                        <Flame className="w-4 h-4" />
                      </div>
                      <div className="font-bold text-sm text-slate-200">{scen.threat_actor}</div>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        scen.severity === "Critical"
                          ? "bg-red-500/20 text-red-400 border border-red-500/30"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                      }`}
                    >
                      {scen.severity}
                    </span>
                  </div>

                  <div className="text-xs font-medium text-slate-300 line-clamp-1">{scen.title}</div>

                  <div className="text-[11px] text-slate-400 line-clamp-2">{scen.summary}</div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                    <span>{scen.steps.length} Attack Stages</span>
                    <span>~{scen.estimated_duration_sec}s Execution</span>
                  </div>

                  {isActiveInSim && (
                    <div className="mt-1 px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono font-semibold flex items-center justify-between">
                      <span>ARMED IN SANDBOX</span>
                      <span>
                        Stage {simState?.current_step_index}/{simState?.total_steps}
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Scenario Details & Attack Stage Progression */}
        <div className="lg:col-span-8 space-y-4">
          {currentScenario && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                      {currentScenario.category}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      {currentScenario.complexity}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mt-1">{currentScenario.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{currentScenario.summary}</p>
                </div>

                <div className="text-right">
                  <div className="text-[11px] font-mono text-slate-400">Target Sector</div>
                  <div className="text-xs font-semibold text-slate-200">{currentScenario.target_sector}</div>
                </div>
              </div>

              {/* Attack Vector Stages Timeline */}
              <div className="space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center justify-between">
                  <span>Attack Kill-Chain Stages ({currentScenario.steps.length})</span>
                  <span className="text-slate-500 font-mono text-[11px]">MITRE ATT&CK & D3FEND Correlation</span>
                </div>

                <div className="space-y-3">
                  {currentScenario.steps.map((step, idx) => {
                    const isInjected = step.status === "Injected";

                    return (
                      <div
                        key={step.step_number}
                        id={`step-card-${step.step_number}`}
                        className={`p-4 rounded-xl border transition-all ${
                          isInjected
                            ? "bg-red-950/20 border-red-500/50 shadow-md shadow-red-950/20"
                            : "bg-slate-950/60 border-slate-800"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold font-mono ${
                                isInjected
                                  ? "bg-red-500 text-white"
                                  : "bg-slate-800 text-slate-400 border border-slate-700"
                              }`}
                            >
                              {step.step_number}
                            </span>
                            <div>
                              <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
                                {step.name}
                                {isInjected && (
                                  <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                                    INJECTED
                                  </span>
                                )}
                              </div>
                              <div className="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5">
                                <span className="flex items-center gap-1 font-mono text-slate-300">
                                  {getDomainIcon(step.domain)} {step.domain}
                                </span>
                                <span>•</span>
                                <span className="font-mono text-red-400">{step.mitre_technique}</span>
                                <span>•</span>
                                <span>{step.technique_name}</span>
                              </div>
                            </div>
                          </div>

                          {step.d3fend_countermeasure_id && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                              D3FEND: {step.d3fend_countermeasure_id}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-slate-400 mt-2">{step.description}</p>

                        <div className="mt-3 p-2.5 rounded-lg bg-black/70 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
                          <div className="text-slate-500 text-[10px] uppercase">Wire Artifact / Injected Payload:</div>
                          <div className="text-amber-300/90 break-all">{step.artifact_payload}</div>
                        </div>

                        <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                          <span className="text-slate-300 font-medium">Expected Trigger:</span> {step.expected_alert}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* IOCs Tag Bar */}
              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">
                  Associated Adversary IOCs & RF Frequencies
                </div>
                <div className="flex flex-wrap gap-2">
                  {currentScenario.iocs_involved.ips.map((ip) => (
                    <span
                      key={ip}
                      className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-cyan-300 font-mono text-[11px] rounded"
                    >
                      IP: {ip}
                    </span>
                  ))}
                  {currentScenario.iocs_involved.domains.map((dom) => (
                    <span
                      key={dom}
                      className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-indigo-300 font-mono text-[11px] rounded"
                    >
                      DOM: {dom}
                    </span>
                  ))}
                  {currentScenario.iocs_involved.rf_frequencies.map((rf) => (
                    <span
                      key={rf}
                      className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-amber-300 font-mono text-[11px] rounded"
                    >
                      RF: {rf}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Real-Time Simulation Event Logs */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Live Sandbox Execution Feed
              </div>
              <span className="text-[11px] font-mono text-slate-500">Auto-tailing</span>
            </div>

            <div className="bg-black/80 rounded-lg p-3 max-h-44 overflow-y-auto font-mono text-xs space-y-1.5 border border-slate-800/80">
              {simState?.logs?.map((log, idx) => (
                <div key={idx} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-slate-500 text-[10px]">{log.timestamp.slice(11, 19)}</span>
                  <span
                    className={`px-1 py-0.2 rounded text-[9px] font-bold uppercase ${
                      log.level === "DEFENSE"
                        ? "bg-emerald-500/20 text-emerald-400"
                        : log.level === "ALERT"
                        ? "bg-red-500/20 text-red-400"
                        : log.level === "WARN"
                        ? "bg-amber-500/20 text-amber-400"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {log.level}
                  </span>
                  <span className="text-slate-300">{log.message}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
