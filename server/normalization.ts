export function ensureIsoTimestamp(ts: any): string {
  try {
    if (!ts) return new Date().toISOString();
    const d = new Date(ts);
    if (isNaN(d.getTime())) return new Date().toISOString();
    return d.toISOString();
  } catch (e) {
    return new Date().toISOString();
  }
}

export function normalizeZeekTsv(line: string, sourceFile?: string) {
  // Parse Zeek TSV format: #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
  const fields = line.split("\t");
  if (fields.length < 8) return null;

  return {
    alert_id: `alt_zeek_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    timestamp: ensureIsoTimestamp(parseFloat(fields[1]) * 1000),
    event: {
      event_id: `evt_zeek_${Date.now()}`,
      event_type: "zeek_connection",
      timestamp: ensureIsoTimestamp(parseFloat(fields[1]) * 1000),
      source_ip: fields[3],
      destination_ip: fields[5],
      source_port: parseInt(fields[4]),
      destination_port: parseInt(fields[6]),
      protocol: fields[7],
      severity: "medium",
      confidence: 0.7,
      details: { line },
    },
    threat_score: { score: 0.4, level: "Medium", confidence: 0.7, sources: ["zeek_normalizer"] },
    threat_level: "Medium",
    priority: "P3",
    summary: `Zeek ${fields[7]} connection from ${fields[3]}:${fields[4]} to ${fields[5]}:${fields[6]}`,
    recommended_actions: [],
    metadata: { source_system: "zeek_normalizer", source_file: sourceFile },
  };
}

export function normalizeSyslog(line: string, sourceFile?: string) {
  // Simple RFC 5424/3164 parser
  const re = /^<\d+>(?:\d+\s+)?(\w+\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}T[\d:Z+.-]+)\s+([\w.-]+)\s+([\w.-]+)(?:\[(\d+)\])?:\s*(.*)$/;
  const match = line.match(re);
  if (!match) return null;

  const timestamp = match[1];
  const hostname = match[2];
  const program = match[3];
  const pid = match[4];
  const message = match[5];

  return {
    alert_id: `alt_syslog_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    timestamp: ensureIsoTimestamp(timestamp),
    event: {
      event_id: `evt_syslog_${Date.now()}`,
      event_type: "syslog_event",
      timestamp: ensureIsoTimestamp(timestamp),
      source_ip: hostname,
      severity: message.toLowerCase().includes("error") || message.toLowerCase().includes("critical") ? "high" : "medium",
      confidence: 0.6,
      details: { hostname, program, pid, message },
    },
    threat_score: { score: 0.3, level: "Low", confidence: 0.6, sources: ["syslog_normalizer"] },
    threat_level: "Low",
    priority: "P3",
    summary: `Syslog from ${hostname} ${program}: ${message.slice(0, 80)}`,
    recommended_actions: [],
    metadata: { source_system: "syslog_normalizer", source_file: sourceFile },
  };
}

export function normalizeWindowsEvent(parsed: any, sourceFile?: string) {
  // Windows Event Log JSON format (EventID, EventData, Computer, TimeCreated)
  const eventId = parsed.System?.EventID?._text || parsed.EventID || null;
  const timestamp = parsed.System?.TimeCreated?._attributes?.SystemTime || parsed.TimeCreated || new Date().toISOString();
  const computer = parsed.System?.Computer?._text || parsed.Computer || "unknown";
  const eventData = parsed.EventData || parsed.System?.EventData || {};

  let eventType = "windows_event";
  let severity = "low";
  let summary = `Windows Event ${eventId}`;

  if (eventId === "1") {
    eventType = "windows_process_create";
    severity = "medium";
    summary = `Process created: ${eventData.CommandLine || ""}`;
  } else if (eventId === "3") {
    eventType = "windows_network";
    severity = "medium";
    summary = `Network connection from ${eventData.SourceIp} to ${eventData.DestinationIp}`;
  } else if (eventId === "13") {
    eventType = "windows_registry";
    severity = "high";
    summary = `Registry modified: ${eventData.TargetObject}`;
  }

  return {
    alert_id: `alt_winevent_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    timestamp: ensureIsoTimestamp(timestamp),
    event: {
      event_id: `evt_winevent_${eventId}`,
      event_type: eventType,
      timestamp: ensureIsoTimestamp(timestamp),
      source_ip: eventData.SourceIp || null,
      destination_ip: eventData.DestinationIp || null,
      username: eventData.User || null,
      severity,
      confidence: 0.85,
      details: { eventData, computer },
    },
    threat_score: { score: severity === "high" ? 0.7 : severity === "medium" ? 0.5 : 0.3, level: severity.charAt(0).toUpperCase() + severity.slice(1), confidence: 0.85, sources: ["windows_event_normalizer"] },
    threat_level: severity === "high" ? "High" : severity === "medium" ? "Medium" : "Low",
    priority: severity === "high" ? "P2" : "P3",
    summary,
    recommended_actions: [],
    metadata: { source_system: "windows_event_normalizer", source_file: sourceFile, event_id: eventId, computer },
  };
}

export function normalizeSuricata(parsed: any, sourceFile?: string) {
  const timestamp = ensureIsoTimestamp(parsed.timestamp || parsed.event?.timestamp || new Date().toISOString());
  const sourceIp = parsed.src_ip || parsed.source || parsed.event?.src_ip || parsed.event?.source_ip || null;
  const destIp = parsed.dest_ip || parsed.dest || parsed.event?.dest_ip || parsed.event?.destination_ip || null;
  const summary = parsed.alert?.signature || parsed.signature || parsed.event?.message || "Suricata Alert";

  return {
    alert_id: `alt_norm_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    timestamp,
    event: {
      event_id: `evt_norm_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
      event_type: "suricata_alert",
      timestamp,
      source_ip: sourceIp,
      destination_ip: destIp,
      username: parsed.user || parsed.username || null,
      severity: (parsed.alert && "high") || parsed.severity || "medium",
      confidence: parsed.confidence ?? 0.9,
      details: parsed,
    },
    threat_score: { score: 0.75, level: "High", confidence: 0.9, sources: ["suricata_norm"] },
    threat_level: "High",
    priority: "P2",
    summary,
    recommended_actions: ["Investigate Source IP"],
    metadata: { source_system: "suricata_eve_normalizer", source_file: sourceFile },
  };
}

export function normalizeGeneric(parsed: any, sourceFile?: string) {
  const timestamp = ensureIsoTimestamp(parsed.timestamp || parsed.event?.timestamp || new Date().toISOString());
  return {
    alert_id: `alt_norm_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    timestamp,
    event: {
      event_id: `evt_norm_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
      event_type: parsed.event_type || parsed.type || "telemetry",
      timestamp,
      source_ip: parsed.source_ip || parsed.src_ip || null,
      destination_ip: parsed.destination_ip || parsed.dest_ip || null,
      username: parsed.username || null,
      severity: parsed.severity || "low",
      confidence: parsed.confidence ?? 0.5,
      details: parsed,
    },
    threat_score: { score: parsed.score ?? 0.5, level: parsed.level || "Medium", confidence: parsed.confidence ?? 0.5, sources: ["generic_norm"] },
    threat_level: parsed.level || "Medium",
    priority: "P3",
    summary: parsed.summary || parsed.message || "Normalized Event",
    recommended_actions: [],
    metadata: { source_system: "generic_normalizer", source_file: sourceFile },
  };
}

export function normalizeToAlert(parsed: any, format: string, sourceFile?: string) {
  try {
    if (format === "suricata_eve" || format === "jsonl") return normalizeSuricata(parsed, sourceFile);
    if (format === "zeek_tsv" && typeof parsed === "string") return normalizeZeekTsv(parsed, sourceFile);
    if (format === "syslog" && typeof parsed === "string") return normalizeSyslog(parsed, sourceFile);
    if (format === "windows_event") return normalizeWindowsEvent(parsed, sourceFile);
    return normalizeGeneric(parsed, sourceFile);
  } catch (e) {
    return normalizeGeneric(parsed, sourceFile);
  }
}
