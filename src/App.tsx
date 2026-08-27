import React, { useState, useEffect, useCallback } from "react";
import { TopBar } from "./components/TopBar";
import { Sidebar } from "./components/Sidebar";
import { MetricsCards } from "./components/MetricsCards";
import { OverviewTab } from "./components/tabs/OverviewTab";
import { AlertsTab } from "./components/tabs/AlertsTab";
import { CasesTab } from "./components/tabs/CasesTab";
import { InvestigationTab } from "./components/tabs/InvestigationTab";
import { HuntingTab } from "./components/tabs/HuntingTab";
import { AutomationTab } from "./components/tabs/AutomationTab";
import { IOCTab } from "./components/tabs/IOCTab";
import { EntitiesTab } from "./components/tabs/EntitiesTab";
import { CapabilitiesTab } from "./components/tabs/CapabilitiesTab";
import { ConnectorsTab } from "./components/tabs/ConnectorsTab";
import { ProfilesTab } from "./components/tabs/ProfilesTab";
import { HealthTab } from "./components/tabs/HealthTab";
import { EventsTab } from "./components/tabs/EventsTab";
import { StreamingTab } from "./components/tabs/StreamingTab";
import { AttackPathForensicsTab } from "./components/tabs/AttackPathForensicsTab";
import { EWTacticalTab } from "./components/tabs/EWTacticalTab";
import { PCAPDissectorTab } from "./components/tabs/PCAPDissectorTab";
import { TacticalGisMapTab } from "./components/tabs/TacticalGisMapTab";
import { D3FENDMatrixTab } from "./components/tabs/D3FENDMatrixTab";
import { AdversarySandboxTab } from "./components/tabs/AdversarySandboxTab";
import { UnifiedTimelineTab } from "./components/tabs/UnifiedTimelineTab";
import { EvidencePackagerTab } from "./components/tabs/EvidencePackagerTab";
import { SitrepGeneratorTab } from "./components/tabs/SitrepGeneratorTab";
import { BlastRadiusTab } from "./components/tabs/BlastRadiusTab";
import { CampaignStudioTab } from "./components/tabs/CampaignStudioTab";

import {
  AlertRecord,
  CaseRecord,
  IOCRecord,
  InvestigationReport,
  Playbook,
  PlaybookRun,
  PipelineStats,
  CapabilityItem,
  ConnectorItem,
  IngestStreamStatus,
  StressTestScenario,
} from "./types";
import {
  Activity,
  ShieldAlert,
  Briefcase,
  Layers,
  Terminal,
  Cpu,
  Database,
  Users,
  Award,
  Network,
  ShieldCheck,
  Heart,
  FileText,
  Zap,
  GitCommit,
  Radio,
  Map,
  Binary,
  Flame,
  Clock,
  PackageCheck,
  GitFork,
  Palette,
} from "lucide-react";

export default function App() {
  // Navigation active tab
  const [activeTab, setActiveTab] = useState<string>("Overview");

  // Filtering states
  const [riskFloor, setRiskFloor] = useState<number>(0.5);
  const [selectedLevels, setSelectedLevels] = useState<string[]>(["Critical", "High", "Medium"]);

  // Backend dataset states
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [iocs, setIocs] = useState<IOCRecord[]>([]);
  const [investigation, setInvestigation] = useState<InvestigationReport | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [playbookRuns, setPlaybookRuns] = useState<PlaybookRun[]>([]);
  const [pipelineStats, setPipelineStats] = useState<PipelineStats | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [runtimeMode, setRuntimeMode] = useState<any>(null);
  const [connectors, setConnectors] = useState<ConnectorItem[]>([]);
  const [connectorSummary, setConnectorSummary] = useState({ implemented: 6, demo_blueprints: 2, total_connectors: 8 });
  const [setupPlan, setSetupPlan] = useState<Array<{ step: number; action: string; status: string }>>([]);
  const [health, setHealth] = useState<any>(null);
  const [streamStatus, setStreamStatus] = useState<IngestStreamStatus | null>(null);
  const [scenarios, setScenarios] = useState<StressTestScenario[]>([]);

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  // Fetch all endpoints
  const fetchAllData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [
        healthRes,
        metricsRes,
        alertsRes,
        casesRes,
        iocsRes,
        attackRes,
        playbooksRes,
        playbookRunsRes,
        capRes,
        connRes,
        streamRes,
      ] = await Promise.all([
        fetch("/api/health").then(r => r.json()).catch(() => null),
        fetch("/api/metrics").then(r => r.json()).catch(() => null),
        fetch("/api/alerts").then(r => r.json()).catch(() => []),
        fetch("/api/cases").then(r => r.json()).catch(() => []),
        fetch("/api/iocs").then(r => r.json()).catch(() => []),
        fetch("/api/attack/timeline").then(r => r.json()).catch(() => null),
        fetch("/api/playbooks").then(r => r.json()).catch(() => []),
        fetch("/api/playbooks/runs").then(r => r.json()).catch(() => []),
        fetch("/api/capabilities").then(r => r.json()).catch(() => null),
        fetch("/api/connectors").then(r => r.json()).catch(() => null),
        fetch("/api/stream/status").then(r => r.json()).catch(() => null),
      ]);

      if (healthRes) setHealth(healthRes);
      if (metricsRes?.pipeline) setPipelineStats(metricsRes.pipeline);
      if (Array.isArray(alertsRes)) setAlerts(alertsRes);
      if (Array.isArray(casesRes)) setCases(casesRes);
      if (Array.isArray(iocsRes)) setIocs(iocsRes);
      if (attackRes) setInvestigation(attackRes);
      if (Array.isArray(playbooksRes)) setPlaybooks(playbooksRes);
      if (Array.isArray(playbookRunsRes)) setPlaybookRuns(playbookRunsRes);

      if (capRes) {
        setCapabilities(capRes.capabilities || []);
        setRuntimeMode(capRes.runtime || null);
        setSetupPlan(capRes.setup_plan || []);
      }

      if (connRes) {
        setConnectors(connRes.catalog || []);
        if (connRes.summary) setConnectorSummary(connRes.summary);
      }

      if (streamRes) {
        setStreamStatus(streamRes);
        if (streamRes.scenarios) setScenarios(streamRes.scenarios);
      }
    } catch (err) {
      console.error("Error fetching SOC state:", err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAllData();
    // Periodic stream poller
    const poller = setInterval(async () => {
      try {
        const streamRes = await fetch("/api/stream/status").then(r => r.json());
        if (streamRes) {
          setStreamStatus(streamRes);
          if (streamRes.is_streaming) {
            // refresh alerts if active stream is injecting detections
            const alertsRes = await fetch("/api/alerts").then(r => r.json()).catch(() => null);
            if (Array.isArray(alertsRes)) setAlerts(alertsRes);
          }
        }
      } catch (e) {
        // ignore periodic poll err
      }
    }, 1500);

    return () => clearInterval(poller);
  }, [fetchAllData]);

  // Handlers for Save Case and Add IOC
  const handleSaveCase = async (casePayload: any) => {
    try {
      await fetch("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(casePayload),
      });
      fetchAllData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddIoc = async (iocPayload: any) => {
    try {
      await fetch("/api/iocs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(iocPayload),
      });
      fetchAllData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunPlaybook = async (playbookId: string, approved: boolean) => {
    const alertContext = alerts[0] || {};
    const res = await fetch("/api/playbooks/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        playbook_id: playbookId,
        alert: alertContext,
        approved,
        actor: "analyst-local",
      }),
    });
    const data = await res.json();
    fetchAllData();
    return data;
  };

  const handleGenerateDemo = async () => {
    setIsGenerating(true);
    try {
      await fetch("/api/telemetry/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: 60 }),
      });
      await fetchAllData();
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleUploadTelemetry = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const newAlerts = Array.isArray(parsed) ? parsed : parsed.events || [];
      if (newAlerts.length > 0) {
        setAlerts(prev => [...newAlerts, ...prev]);
      }
    } catch (err) {
      console.error("Invalid JSON file uploaded:", err);
    }
  };

  const handleStartStream = async (eps: number, scenarioId: string) => {
    try {
      const res = await fetch("/api/stream/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ eps, scenario_id: scenarioId }),
      });
      const data = await res.json();
      if (data.stream) setStreamStatus(data.stream);
    } catch (err) {
      console.error("Error starting stream:", err);
    }
  };

  const handleStopStream = async () => {
    try {
      const res = await fetch("/api/stream/stop", { method: "POST" });
      const data = await res.json();
      if (data.stream) setStreamStatus(data.stream);
    } catch (err) {
      console.error("Error stopping stream:", err);
    }
  };

  const handleAdjustEps = async (eps: number) => {
    try {
      const res = await fetch("/api/stream/adjust", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ eps }),
      });
      const data = await res.json();
      if (data.stream) setStreamStatus(data.stream);
    } catch (err) {
      console.error("Error adjusting EPS:", err);
    }
  };

  const handleRawIngest = async (format: string, content: string, sensorTag: string) => {
    const res = await fetch("/api/ingest/raw", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format, content, sensor_tag: sensorTag }),
    });
    const data = await res.json();
    fetchAllData();
    return data;
  };

  const handleExportBundle = () => {
    window.location.href = "/api/export/bundle";
  };

  // Filtered alerts for display
  const filteredAlerts = alerts.filter(a => {
    const score = a.score ?? a.threat_score?.score ?? 0.5;
    const lvl = a.level || a.threat_level || "High";
    return score >= riskFloor && selectedLevels.includes(lvl);
  });

  const criticalCount = alerts.filter(a => a.level === "Critical").length;
  const highCount = alerts.filter(a => a.level === "High").length;
  const detectionCount = alerts.filter(a => a.patterns && a.patterns !== "Routine").length || alerts.length;
  const entitySet = new Set<string>();
  alerts.forEach(a => {
    if (a.event?.source_ip || a.source_ip) entitySet.add(a.event?.source_ip || a.source_ip!);
    if (a.event?.destination_ip || a.destination_ip) entitySet.add(a.event?.destination_ip || a.destination_ip!);
  });

  const tabs = [
    { id: "Overview", icon: Activity, label: "Overview" },
    { id: "BlastRadius", icon: GitFork, label: "Blast Radius Graph", badge: "Physics" },
    { id: "Sitrep", icon: FileText, label: "SITREP Briefing", badge: "NATO" },
    { id: "CampaignStudio", icon: Palette, label: "Campaign Studio", badge: "Builder" },
    { id: "AdversarySandbox", icon: Flame, label: "Adversary Sandbox", badge: "Sim" },
    { id: "UnifiedTimeline", icon: Clock, label: "Unified Timeline", badge: "Live" },
    { id: "EvidencePackager", icon: PackageCheck, label: "STIX 2.1 Packager", badge: "AirGap" },
    { id: "TacticalGIS", icon: Map, label: "Tactical 3D GIS", badge: "Live" },
    { id: "PCAP", icon: Binary, label: "PCAP & DPI", badge: "Live" },
    { id: "D3FEND", icon: ShieldCheck, label: "D3FEND Matrix", badge: "MITRE" },
    { id: "EWTactical", icon: Radio, label: "EW & RF Fusion", badge: "Audio DSP" },
    { id: "Hunting", icon: Terminal, label: "AI Threat Hunting", badge: "Gemini" },
    { id: "Streaming", icon: Zap, label: "Live Stream / Cluster", badge: streamStatus?.is_streaming ? streamStatus.actual_eps : undefined },
    { id: "AttackPath", icon: GitCommit, label: "Attack Path & Forensics" },
    { id: "Alerts", icon: ShieldAlert, label: "Alert Triage", badge: filteredAlerts.length },
    { id: "Cases", icon: Briefcase, label: "Cases", badge: cases.filter(c => c.status !== "Closed").length },
    { id: "Investigation", icon: Layers, label: "Investigation" },
    { id: "Automation", icon: Cpu, label: "Automation" },
    { id: "IOCs", icon: Database, label: "IOC Watchlist", badge: iocs.length },
    { id: "Entities", icon: Users, label: "Entities" },
    { id: "Capabilities", icon: Award, label: "Capabilities" },
    { id: "Connectors", icon: Network, label: "Connectors" },
    { id: "Profiles", icon: ShieldCheck, label: "Profiles" },
    { id: "Health", icon: Heart, label: "Health" },
    { id: "Events", icon: FileText, label: "Events" },
  ];


  return (
    <div className="min-h-screen bg-[#0b0f14] text-[#e8edf2] p-3 sm:p-5 font-sans">
      <div className="max-w-7xl mx-auto space-y-4">
        {/* Top Header */}
        <TopBar
          healthStatus={health}
          onRefresh={fetchAllData}
          isRefreshing={isRefreshing}
          onExportBundle={handleExportBundle}
        />

        {/* 6 SOC KPIs */}
        <MetricsCards
          eventsCount={alerts.length || 117}
          alertsCount={filteredAlerts.length}
          criticalCount={criticalCount}
          highCount={highCount}
          detectionsCount={detectionCount}
          entitiesCount={entitySet.size || 14}
          openCasesCount={cases.filter(c => c.status !== "Closed").length}
          totalCasesCount={cases.length}
          iocsCount={iocs.length}
          pipelineProcessed={pipelineStats?.events_processed || 12212}
        />

        {/* Main Dashboard Layout: Sidebar + Tab Navigation + Active Content */}
        <div className="flex flex-col lg:flex-row gap-4 items-start">
          <Sidebar
            riskFloor={riskFloor}
            onRiskFloorChange={setRiskFloor}
            selectedLevels={selectedLevels}
            onToggleLevel={lvl => {
              setSelectedLevels(prev =>
                prev.includes(lvl) ? prev.filter(x => x !== lvl) : [...prev, lvl]
              );
            }}
            onGenerateDemo={handleGenerateDemo}
            isGenerating={isGenerating}
            onUploadTelemetry={handleUploadTelemetry}
            alertsCount={filteredAlerts.length}
            totalLoadedEvents={alerts.length}
          />

          <main className="flex-1 w-full overflow-hidden space-y-4">
            {/* Tab navigation pills bar */}
            <div className="flex items-center gap-1.5 p-1.5 rounded-lg bg-[#111821] border border-[#243244] overflow-x-auto">
              {tabs.map(tab => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-all ${
                      isActive
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                        : "text-[#94a3b8] hover:text-[#e8edf2] hover:bg-[#151e29]"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                    {tab.badge !== undefined && tab.badge !== 0 && tab.badge !== "" && (
                      <span className="px-1.5 py-0.2 rounded-full bg-[#151e29] border border-[#243244] text-[10px] font-mono text-cyan-400">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Tab Content Display */}
            <div className="transition-all duration-200">
              {activeTab === "Overview" && (
                <OverviewTab alerts={filteredAlerts} pipelineStats={pipelineStats} />
              )}
              {activeTab === "BlastRadius" && <BlastRadiusTab />}
              {activeTab === "Sitrep" && <SitrepGeneratorTab />}
              {activeTab === "CampaignStudio" && (
                <CampaignStudioTab
                  onNavigateToSandbox={() => setActiveTab("AdversarySandbox")}
                />
              )}
              {activeTab === "AdversarySandbox" && <AdversarySandboxTab />}
              {activeTab === "UnifiedTimeline" && <UnifiedTimelineTab />}
              {activeTab === "EvidencePackager" && <EvidencePackagerTab />}
              {activeTab === "TacticalGIS" && <TacticalGisMapTab />}

              {activeTab === "PCAP" && <PCAPDissectorTab />}
              {activeTab === "D3FEND" && <D3FENDMatrixTab />}
              {activeTab === "EWTactical" && (
                <EWTacticalTab alerts={filteredAlerts} />
              )}
              {activeTab === "Streaming" && (
                <StreamingTab
                  streamStatus={streamStatus}
                  scenarios={scenarios}
                  onStartStream={handleStartStream}
                  onStopStream={handleStopStream}
                  onAdjustEps={handleAdjustEps}
                  onRawIngest={handleRawIngest}
                />
              )}
              {activeTab === "AttackPath" && <AttackPathForensicsTab />}
              {activeTab === "Alerts" && (
                <AlertsTab
                  alerts={filteredAlerts}
                  onSaveCase={handleSaveCase}
                  onAddIoc={handleAddIoc}
                />
              )}
              {activeTab === "Cases" && (
                <CasesTab cases={cases} onSaveCase={handleSaveCase} />
              )}
              {activeTab === "Investigation" && (
                <InvestigationTab investigation={investigation} />
              )}
              {activeTab === "Hunting" && <HuntingTab />}
              {activeTab === "Automation" && (
                <AutomationTab
                  playbooks={playbooks}
                  playbookRuns={playbookRuns}
                  onRunPlaybook={handleRunPlaybook}
                />
              )}
              {activeTab === "IOCs" && (
                <IOCTab iocs={iocs} onAddIoc={handleAddIoc} />
              )}
              {activeTab === "Entities" && <EntitiesTab alerts={filteredAlerts} />}
              {activeTab === "Capabilities" && (
                <CapabilitiesTab
                  capabilities={capabilities}
                  runtimeMode={runtimeMode}
                />
              )}
              {activeTab === "Connectors" && (
                <ConnectorsTab
                  connectors={connectors}
                  summary={connectorSummary}
                  setupPlan={setupPlan}
                />
              )}
              {activeTab === "Profiles" && <ProfilesTab alerts={filteredAlerts} />}
              {activeTab === "Health" && (
                <HealthTab health={health} onRefreshHealth={fetchAllData} />
              )}
              {activeTab === "Events" && <EventsTab alerts={filteredAlerts} />}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
