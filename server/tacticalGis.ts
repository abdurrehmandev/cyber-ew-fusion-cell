import {
  TacticalMapState,
  TacticalSensorStation,
  TacticalCyberAsset,
  JammingContourZone,
} from "../src/types";

let tacticalSensors: TacticalSensorStation[] = [
  {
    id: "SIGINT-ALPHA",
    name: "Sensor Array Alpha (Perimeter Mast)",
    callsign: "MAST-01",
    type: "Fixed SIGINT Mast",
    lat: 38.8977,
    lon: -77.0365,
    elevation_m: 45,
    coverage_radius_km: 18.5,
    frequency_band: "30 MHz - 6.0 GHz",
    status: "Active Tracking",
    bearing_coverage_arc: [0, 360],
    health_pct: 99.4,
  },
  {
    id: "SIGINT-BRAVO",
    name: "Airfield Phased Radar Node",
    callsign: "RADAR-AIR-02",
    type: "Airfield Radar",
    lat: 38.905,
    lon: -77.05,
    elevation_m: 22,
    coverage_radius_km: 25.0,
    frequency_band: "1.0 GHz - 18.0 GHz",
    status: "ECM Active",
    bearing_coverage_arc: [45, 270],
    health_pct: 94.2,
  },
  {
    id: "SIGINT-CHARLIE",
    name: "Mobile SDR Patrol Unit Charlie",
    callsign: "ROVER-09",
    type: "Mobile SDR Patrol",
    lat: 38.889,
    lon: -77.025,
    elevation_m: 12,
    coverage_radius_km: 8.0,
    frequency_band: "400 MHz - 3.8 GHz",
    status: "Active Tracking",
    bearing_coverage_arc: [0, 360],
    health_pct: 98.1,
  },
  {
    id: "SIGINT-DELTA",
    name: "HQ Roof Directional SIGINT Array",
    callsign: "ROOF-ARRAY-4",
    type: "Roof Array",
    lat: 38.912,
    lon: -77.018,
    elevation_m: 65,
    coverage_radius_km: 14.0,
    frequency_band: "100 MHz - 12.0 GHz",
    status: "Active Tracking",
    bearing_coverage_arc: [180, 360],
    health_pct: 100.0,
  },
];

let tacticalCyberAssets: TacticalCyberAsset[] = [
  {
    id: "ASSET-DC01",
    name: "Primary Active Directory DC-01",
    role: "Domain Controller",
    lat: 38.898,
    lon: -77.035,
    ip: "10.0.0.10",
    threat_level: "Critical",
    compromise_status: "Targeted",
  },
  {
    id: "ASSET-DMZ",
    name: "DMZ Edge Gateway / Reverse Proxy",
    role: "DMZ Gateway",
    lat: 38.902,
    lon: -77.042,
    ip: "10.0.1.1",
    threat_level: "High",
    compromise_status: "Targeted",
  },
  {
    id: "ASSET-SCADA",
    name: "OT Substation Power Controller",
    role: "SCADA Substation",
    lat: 38.887,
    lon: -77.029,
    ip: "10.0.4.15",
    threat_level: "High",
    compromise_status: "Compromised",
  },
  {
    id: "ASSET-FINANCE",
    name: "Finance Database Cluster (DB-01)",
    role: "Finance Subnet",
    lat: 38.909,
    lon: -77.022,
    ip: "10.0.2.80",
    threat_level: "Medium",
    compromise_status: "Secure",
  },
  {
    id: "ASSET-ROGUE-C2",
    name: "Hostile Tactical SDR Transmitter",
    role: "C2 Node (Hostile)",
    lat: 38.893,
    lon: -77.046,
    ip: "198.51.100.42",
    threat_level: "Critical",
    compromise_status: "Targeted",
  },
];

let jammingZones: JammingContourZone[] = [
  {
    id: "JAM-ZONE-01",
    name: "GPS L1 Spoofing Degradation Bubble",
    center_lat: 38.895,
    center_lon: -77.038,
    radius_m: 1200,
    band_affected: "GPS L1 (1575.42 MHz)",
    interference_dbm: -38,
    severity: "Severe Jamming",
  },
  {
    id: "JAM-ZONE-02",
    name: "Tactical Wi-Fi Mesh Jamming Corridor",
    center_lat: 38.903,
    center_lon: -77.044,
    radius_m: 750,
    band_affected: "Wi-Fi 2.4 GHz",
    interference_dbm: -46,
    severity: "Moderate Degradation",
  },
  {
    id: "JAM-ZONE-03",
    name: "UAV Telemetry Hijack Sector",
    center_lat: 38.891,
    center_lon: -77.031,
    radius_m: 900,
    band_affected: "UAV 433 MHz",
    interference_dbm: -41,
    severity: "Severe Jamming",
  },
];

export function getTacticalMapState(): TacticalMapState {
  return {
    map_center: [38.898, -77.036],
    zoom_level: 14,
    sensors: tacticalSensors,
    cyber_assets: tacticalCyberAssets,
    jamming_zones: jammingZones,
    active_bearing_lines: [
      {
        station_id: "SIGINT-ALPHA",
        bearing_deg: 247.5,
        target_signal_id: "SIG-9912",
        is_hostile: true,
      },
      {
        station_id: "SIGINT-BRAVO",
        bearing_deg: 132.0,
        target_signal_id: "SIG-9912",
        is_hostile: true,
      },
      {
        station_id: "SIGINT-CHARLIE",
        bearing_deg: 312.0,
        target_signal_id: "SIG-9912",
        is_hostile: true,
      },
      {
        station_id: "SIGINT-DELTA",
        bearing_deg: 218.0,
        target_signal_id: "SIG-9912",
        is_hostile: true,
      },
    ],
  };
}

export function updateSensorStatus(sensorId: string, status: any) {
  const sensor = tacticalSensors.find((s) => s.id === sensorId);
  if (sensor) {
    sensor.status = status;
  }
  return sensor;
}
