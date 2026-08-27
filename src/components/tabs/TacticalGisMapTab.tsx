import React, { useState, useEffect } from "react";
import {
  Map,
  Radio,
  Crosshair,
  Shield,
  Layers,
  Compass,
  AlertTriangle,
  Zap,
  Activity,
  Maximize2,
  Minimize2,
  RefreshCw,
  Server,
} from "lucide-react";
import {
  TacticalMapState,
  TacticalSensorStation,
  TacticalCyberAsset,
  JammingContourZone,
} from "../../types";

export const TacticalGisMapTab: React.FC = () => {
  const [mapState, setMapState] = useState<TacticalMapState | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<any | null>(null);
  const [selectedEntityType, setSelectedEntityType] = useState<"sensor" | "asset" | "jamming" | null>(null);
  const [showArcs, setShowArcs] = useState(true);
  const [showJamming, setShowJamming] = useState(true);
  const [showAssets, setShowAssets] = useState(true);
  const [showBearings, setShowBearings] = useState(true);
  const [showGrid, setShowGrid] = useState(true);
  const [isUpdatingSensor, setIsUpdatingSensor] = useState(false);
  const [ecmStatusMessage, setEcmStatusMessage] = useState<string | null>(null);

  const fetchGisState = async () => {
    try {
      const res = await fetch("/api/tactical/gis-state");
      const data: TacticalMapState = await res.json();
      setMapState(data);
      if (!selectedEntity && data.sensors.length > 0) {
        setSelectedEntity(data.sensors[0]);
        setSelectedEntityType("sensor");
      }
    } catch (err) {
      console.error("Error fetching tactical GIS state:", err);
    }
  };

  useEffect(() => {
    fetchGisState();
  }, []);

  const handleUpdateSensorStatus = async (sensorId: string, newStatus: string) => {
    setIsUpdatingSensor(true);
    try {
      const res = await fetch("/api/tactical/sensor/update", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sensor_id: sensorId, status: newStatus }),
      });
      const data = await res.json();
      if (data.sensor) {
        setMapState((prev) => {
          if (!prev) return null;
          return {
            ...prev,
            sensors: prev.sensors.map((s) => (s.id === sensorId ? data.sensor : s)),
          };
        });
        setSelectedEntity(data.sensor);
        setEcmStatusMessage(`Sensor ${sensorId} updated: ${newStatus}`);
        setTimeout(() => setEcmStatusMessage(null), 3000);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsUpdatingSensor(false);
    }
  };

  // Convert lat/lon relative to map center to SVG canvas X/Y (viewBox: 800 x 500)
  const centerLat = mapState?.map_center[0] || 38.898;
  const centerLon = mapState?.map_center[1] || -77.036;

  const latLonToSvg = (lat: number, lon: number) => {
    const scaleX = 14000;
    const scaleY = 14000;
    const x = 400 + (lon - centerLon) * scaleX;
    const y = 250 - (lat - centerLat) * scaleY;
    return { x, y };
  };

  // Triangulation calculation point for the hostile emitter
  const hostileFixCoords = latLonToSvg(38.893, -77.046);

  return (
    <div className="space-y-4">
      {/* Top Controls Bar */}
      <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[#e8edf2] flex items-center gap-2">
            <Map className="w-5 h-5 text-cyan-400" />
            Geospatial Tactical Map &amp; 3D SIGINT Sensor Deployment
          </h2>
          <p className="text-xs text-[#94a3b8]">
            Real-time geospatial tracking of SDR SIGINT array stations, AoA bearing lines, GPS spoofing jamming zones, and cyber infrastructure nodes
          </p>
        </div>

        {/* Layer Toggles */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-[11px] text-[#94a3b8] mr-1 flex items-center gap-1">
            <Layers className="w-3.5 h-3.5" />
            Layers:
          </span>
          <button
            onClick={() => setShowArcs(!showArcs)}
            className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors ${
              showArcs ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
            }`}
          >
            Sensors &amp; Arcs
          </button>
          <button
            onClick={() => setShowBearings(!showBearings)}
            className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors ${
              showBearings ? "bg-red-500/20 text-red-300 border-red-500/40" : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
            }`}
          >
            AoA Bearings
          </button>
          <button
            onClick={() => setShowJamming(!showJamming)}
            className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors ${
              showJamming ? "bg-amber-500/20 text-amber-300 border-amber-500/40" : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
            }`}
          >
            Jamming Zones
          </button>
          <button
            onClick={() => setShowAssets(!showAssets)}
            className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors ${
              showAssets ? "bg-purple-500/20 text-purple-300 border-purple-500/40" : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
            }`}
          >
            Cyber Assets
          </button>
          <button
            onClick={() => setShowGrid(!showGrid)}
            className={`px-2 py-1 rounded text-[11px] font-medium border transition-colors ${
              showGrid ? "bg-slate-500/20 text-slate-300 border-slate-500/40" : "bg-[#151e29] text-[#94a3b8] border-[#243244]"
            }`}
          >
            MGRS Grid
          </button>
        </div>
      </div>

      {ecmStatusMessage && (
        <div className="p-2.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400 animate-spin" />
          <span>{ecmStatusMessage}</span>
        </div>
      )}

      {/* Main Map Canvas & Entity Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* SVG Tactical Vector Map (2 cols) */}
        <div className="lg:col-span-2 p-4 rounded-lg bg-[#0b0f14] border border-[#243244] relative overflow-hidden flex flex-col justify-between min-h-[460px]">
          {/* Top Canvas HUD Overlay */}
          <div className="flex items-center justify-between z-10 text-[11px] font-mono text-[#94a3b8] mb-2 pointer-events-none">
            <div className="flex items-center gap-2 bg-[#111821]/80 px-2 py-1 rounded border border-[#243244]">
              <Compass className="w-3.5 h-3.5 text-cyan-400 animate-spin" style={{ animationDuration: "20s" }} />
              <span>GRID: 18S UJ 2348 0912 | WGS84: 38.898°N, 77.036°W</span>
            </div>
            <div className="bg-[#111821]/80 px-2 py-1 rounded border border-[#243244] text-emerald-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>4 STATIONS ONLINE</span>
            </div>
          </div>

          {/* Interactive SVG Tactical Viewport */}
          <div className="w-full h-full relative flex items-center justify-center">
            <svg
              viewBox="0 0 800 480"
              className="w-full h-[400px] select-none rounded bg-[#070b10] border border-[#1e2a38]"
            >
              <defs>
                {/* Tactical radar scan gradient */}
                <radialGradient id="radarGrid" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                </radialGradient>

                <radialGradient id="jammingGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.35" />
                  <stop offset="70%" stopColor="#ef4444" stopOpacity="0.15" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
                </radialGradient>

                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Grid Lines */}
              {showGrid && (
                <g stroke="#1a2636" strokeWidth="0.8" strokeDasharray="3 3">
                  <line x1="0" y1="80" x2="800" y2="80" />
                  <line x1="0" y1="160" x2="800" y2="160" />
                  <line x1="0" y1="240" x2="800" y2="240" />
                  <line x1="0" y1="320" x2="800" y2="320" />
                  <line x1="0" y1="400" x2="800" y2="400" />

                  <line x1="160" y1="0" x2="160" y2="480" />
                  <line x1="320" y1="0" x2="320" y2="480" />
                  <line x1="480" y1="0" x2="480" y2="480" />
                  <line x1="640" y1="0" x2="640" y2="480" />
                </g>
              )}

              {/* Range Rings from Center */}
              <circle cx="400" cy="240" r="120" fill="none" stroke="#243244" strokeWidth="0.8" strokeDasharray="4 4" />
              <circle cx="400" cy="240" r="220" fill="none" stroke="#243244" strokeWidth="0.8" strokeDasharray="4 4" />
              <circle cx="400" cy="240" r="320" fill="none" stroke="#243244" strokeWidth="0.8" strokeDasharray="4 4" />

              {/* Jamming Zones (Translucent Bubbles) */}
              {showJamming &&
                mapState?.jamming_zones.map((zone) => {
                  const pos = latLonToSvg(zone.center_lat, zone.center_lon);
                  const radius = (zone.radius_m / 1000) * 80;
                  return (
                    <g
                      key={zone.id}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelectedEntity(zone);
                        setSelectedEntityType("jamming");
                      }}
                    >
                      <circle cx={pos.x} cy={pos.y} r={radius} fill="url(#jammingGrad)" stroke="#ef4444" strokeWidth="1" strokeDasharray="2 2" />
                      <circle cx={pos.x} cy={pos.y} r={radius * 0.4} fill="#ef4444" fillOpacity="0.2" />
                      <text x={pos.x} y={pos.y + 4} fill="#fca5a5" fontSize="9" textAnchor="middle" fontFamily="monospace">
                        {zone.band_affected} ({zone.interference_dbm} dBm)
                      </text>
                    </g>
                  );
                })}

              {/* Sensor Coverage Arcs & Icons */}
              {showArcs &&
                mapState?.sensors.map((sensor) => {
                  const pos = latLonToSvg(sensor.lat, sensor.lon);
                  const radius = sensor.coverage_radius_km * 7.5;
                  const isSelected = selectedEntity?.id === sensor.id;
                  return (
                    <g
                      key={sensor.id}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelectedEntity(sensor);
                        setSelectedEntityType("sensor");
                      }}
                    >
                      <circle
                        cx={pos.x}
                        cy={pos.y}
                        r={radius}
                        fill="none"
                        stroke={sensor.status === "ECM Active" ? "#f59e0b" : "#06b6d4"}
                        strokeWidth="1"
                        strokeOpacity="0.3"
                        strokeDasharray="4 4"
                      />
                      <circle
                        cx={pos.x}
                        cy={pos.y}
                        r={isSelected ? 8 : 6}
                        fill={sensor.status === "ECM Active" ? "#f59e0b" : "#06b6d4"}
                        fillOpacity="0.9"
                        filter="url(#glow)"
                      />
                      <text x={pos.x} y={pos.y - 10} fill="#67e8f9" fontSize="10" fontWeight="bold" textAnchor="middle" fontFamily="monospace">
                        {sensor.callsign}
                      </text>
                    </g>
                  );
                })}

              {/* Angle-of-Arrival (AoA) Bearing Lines to Triangulation Hostile Fix */}
              {showBearings &&
                mapState?.sensors.map((sensor) => {
                  const sensorPos = latLonToSvg(sensor.lat, sensor.lon);
                  return (
                    <g key={`bearing-${sensor.id}`}>
                      <line
                        x1={sensorPos.x}
                        y1={sensorPos.y}
                        x2={hostileFixCoords.x}
                        y2={hostileFixCoords.y}
                        stroke="#ef4444"
                        strokeWidth="1.5"
                        strokeDasharray="6 4"
                        strokeOpacity="0.8"
                      />
                      <circle cx={hostileFixCoords.x} cy={hostileFixCoords.y} r="16" fill="none" stroke="#ef4444" strokeWidth="1" strokeDasharray="3 3">
                        <animate attributeName="r" values="12;24;12" dur="2.5s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.8;0.2;0.8" dur="2.5s" repeatCount="indefinite" />
                      </circle>
                    </g>
                  );
                })}

              {/* Hostile Triangulated Fix Point */}
              <g className="cursor-pointer">
                <circle cx={hostileFixCoords.x} cy={hostileFixCoords.y} r="6" fill="#ef4444" filter="url(#glow)" />
                <text x={hostileFixCoords.x} y={hostileFixCoords.y + 16} fill="#f87171" fontSize="10" fontWeight="bold" textAnchor="middle" fontFamily="monospace">
                  TARGET FIX (CEP: 45m)
                </text>
              </g>

              {/* Cyber Assets */}
              {showAssets &&
                mapState?.cyber_assets.map((asset) => {
                  const pos = latLonToSvg(asset.lat, asset.lon);
                  const isSelected = selectedEntity?.id === asset.id;
                  const isCompromised = asset.compromise_status === "Compromised" || asset.compromise_status === "Targeted";
                  return (
                    <g
                      key={asset.id}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelectedEntity(asset);
                        setSelectedEntityType("asset");
                      }}
                    >
                      <rect
                        x={pos.x - 7}
                        y={pos.y - 7}
                        width="14"
                        height="14"
                        rx="3"
                        fill={isCompromised ? "#dc2626" : "#8b5cf6"}
                        stroke={isSelected ? "#38bdf8" : "#243244"}
                        strokeWidth={isSelected ? "2" : "1"}
                      />
                      <text x={pos.x} y={pos.y + 18} fill="#e2e8f0" fontSize="9" textAnchor="middle" fontFamily="sans-serif">
                        {asset.name.split(" ")[0]} ({asset.ip})
                      </text>
                    </g>
                  );
                })}
            </svg>
          </div>

          {/* Bottom Coordinates Status */}
          <div className="flex items-center justify-between z-10 text-[11px] font-mono text-[#94a3b8] mt-2 pt-2 border-t border-[#1e2a38]">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400">Triangulation Fix:</span> 38.8930°N, 77.0460°W (Confidence: 97.8% | 4 Sensor AoA Intersect)
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchGisState}
                className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                title="Refresh GIS State"
              >
                <RefreshCw className="w-3 h-3" />
                Sync Telemetry
              </button>
            </div>
          </div>
        </div>

        {/* Entity Inspector & Command Panel (1 col) */}
        <div className="p-4 rounded-lg bg-[#111821] border border-[#243244] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#1e2a38]">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#e8edf2]">
              <Crosshair className="w-4 h-4 text-cyan-400" />
              <span>Tactical Entity Inspector</span>
            </div>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#151e29] text-cyan-300 border border-[#243244]">
              {selectedEntityType || "NONE"}
            </span>
          </div>

          {selectedEntity ? (
            <div className="space-y-3 text-xs">
              {/* Sensor Station Card */}
              {selectedEntityType === "sensor" && (
                <>
                  <div className="p-3 rounded bg-[#0b0f14] border border-[#243244] space-y-2">
                    <div className="text-sm font-semibold text-cyan-300">{selectedEntity.name}</div>
                    <div className="text-[11px] text-[#94a3b8] font-mono">Callsign: {selectedEntity.callsign}</div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                      <div>
                        <span className="text-[#94a3b8]">Status:</span>{" "}
                        <span className={`font-bold ${selectedEntity.status === "ECM Active" ? "text-amber-400" : "text-emerald-400"}`}>
                          {selectedEntity.status}
                        </span>
                      </div>
                      <div>
                        <span className="text-[#94a3b8]">Health:</span> {selectedEntity.health_pct}%
                      </div>
                      <div>
                        <span className="text-[#94a3b8]">Band:</span> {selectedEntity.frequency_band}
                      </div>
                      <div>
                        <span className="text-[#94a3b8]">Coverage:</span> {selectedEntity.coverage_radius_km} km
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="space-y-2">
                    <div className="text-[11px] font-semibold text-[#94a3b8]">Station Command Actions:</div>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => handleUpdateSensorStatus(selectedEntity.id, "ECM Active")}
                        disabled={isUpdatingSensor}
                        className="px-2.5 py-1.5 rounded bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-[11px] font-semibold transition-colors flex items-center justify-center gap-1"
                      >
                        <Zap className="w-3 h-3" />
                        Engage ECM
                      </button>
                      <button
                        onClick={() => handleUpdateSensorStatus(selectedEntity.id, "Active Tracking")}
                        disabled={isUpdatingSensor}
                        className="px-2.5 py-1.5 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-semibold transition-colors flex items-center justify-center gap-1"
                      >
                        <Radio className="w-3 h-3" />
                        Tracking Mode
                      </button>
                    </div>
                  </div>
                </>
              )}

              {/* Cyber Asset Card */}
              {selectedEntityType === "asset" && (
                <div className="p-3 rounded bg-[#0b0f14] border border-[#243244] space-y-2">
                  <div className="text-sm font-semibold text-purple-300">{selectedEntity.name}</div>
                  <div className="text-[11px] text-[#94a3b8] font-mono">Role: {selectedEntity.role}</div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                    <div>
                      <span className="text-[#94a3b8]">IP Address:</span> {selectedEntity.ip}
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Threat Level:</span>{" "}
                      <span className="text-red-400 font-bold">{selectedEntity.threat_level}</span>
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Status:</span>{" "}
                      <span className="text-amber-400">{selectedEntity.compromise_status}</span>
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Coordinates:</span> {selectedEntity.lat.toFixed(3)}, {selectedEntity.lon.toFixed(3)}
                    </div>
                  </div>
                </div>
              )}

              {/* Jamming Zone Card */}
              {selectedEntityType === "jamming" && (
                <div className="p-3 rounded bg-[#0b0f14] border border-red-500/40 space-y-2">
                  <div className="text-sm font-semibold text-red-300">{selectedEntity.name}</div>
                  <div className="text-[11px] text-[#94a3b8]">Band Affected: {selectedEntity.band_affected}</div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                    <div>
                      <span className="text-[#94a3b8]">Interference:</span>{" "}
                      <span className="text-red-400 font-bold">{selectedEntity.interference_dbm} dBm</span>
                    </div>
                    <div>
                      <span className="text-[#94a3b8]">Radius:</span> {selectedEntity.radius_m}m
                    </div>
                    <div className="col-span-2">
                      <span className="text-[#94a3b8]">Severity:</span>{" "}
                      <span className="text-red-300 font-bold">{selectedEntity.severity}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-[#94a3b8]">
              Click any sensor station, cyber asset, or jamming zone on the map to inspect telemetry details.
            </div>
          )}

          {/* Triangulation Summary Box */}
          <div className="p-3 rounded bg-[#0b0f14] border border-[#243244] space-y-1.5 text-xs">
            <div className="font-semibold text-cyan-300 text-[11px] flex items-center gap-1">
              <Crosshair className="w-3.5 h-3.5" />
              <span>Multi-Station Triangulation Matrix</span>
            </div>
            <div className="text-[11px] text-[#94a3b8]">
              Target Emitter: <strong className="text-red-400">SIG-9912 (Hostile Jammer / C2)</strong>
            </div>
            <div className="text-[10px] font-mono text-slate-300 space-y-0.5">
              <div>MAST-01 (Station Alpha): Bearing 247.5°</div>
              <div>RADAR-02 (Station Bravo): Bearing 132.0°</div>
              <div>ROVER-09 (Station Charlie): Bearing 312.0°</div>
              <div>ROOF-04 (Station Delta): Bearing 218.0°</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
