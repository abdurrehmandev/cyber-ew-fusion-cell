// Output Engine: Multi-format alert exporter (CEF, STIX, CSV, JSONL)

export interface OutputFormat {
  format: 'jsonl' | 'cef' | 'stix' | 'csv' | 'syslog';
  timestamp: string;
  content: string;
}

class OutputEngine {
  /**
   * Convert alert to CEF (Common Event Format)
   * CEF:0|vendor|product|version|signatureId|name|severity|extensionFields
   */
  toCEF(alert: any): string {
    const vendor = 'CyberEW';
    const product = 'FusionCell';
    const version = '1.0';
    const signatureId = alert.alert_id || 'unknown';
    const name = alert.summary || 'Security Alert';
    const severity = this.mapSeverityToCEF(alert.threat_level);

    const extensions = {
      src: alert.event?.source_ip || '',
      spt: alert.event?.source_port || '',
      dst: alert.event?.destination_ip || '',
      dpt: alert.event?.destination_port || '',
      proto: alert.event?.protocol || '',
      cs1Label: 'ThreatScore',
      cs1: (alert.threat_score?.score || 0).toFixed(2),
      cs2Label: 'ThreatLevel',
      cs2: alert.threat_level || '',
      cs3Label: 'Priority',
      cs3: alert.priority || '',
      suser: alert.event?.username || '',
      request: alert.summary || '',
      msg: JSON.stringify(alert.recommended_actions || []),
      deviceExternalId: alert.metadata?.source_system || '',
      end: new Date(alert.timestamp).getTime(),
      severity: this.mapSeverityToCEF(alert.threat_level),
    };

    const extensionStr = Object.entries(extensions)
      .filter(([_, v]) => v !== '' && v !== null && v !== undefined)
      .map(([k, v]) => `${k}=${v}`)
      .join(' ');

    return `CEF:0|${vendor}|${product}|${version}|${signatureId}|${name}|${severity}|${extensionStr}`;
  }

  /**
   * Convert alert to STIX 2.0-like JSON format (simplified)
   */
  toSTIX(alert: any): string {
    const stixObject = {
      type: 'observed-data',
      id: `observed-data--${alert.alert_id}`,
      created_time_precision: 'millis',
      created: alert.timestamp,
      modified: alert.timestamp,
      first_observed: alert.timestamp,
      last_observed: alert.timestamp,
      number_observed: 1,
      object_refs: this.buildSTIXRefs(alert),
      cyber_observable_objects: this.buildSTIXObservables(alert),
      x_threat_score: {
        score: alert.threat_score?.score || 0,
        level: alert.threat_level || 'Unknown',
        confidence: alert.threat_score?.confidence || 0,
      },
      x_correlation_summary: alert._correlation_summary || {},
      x_behavior_analysis: alert.behavior_analysis || {},
    };

    return JSON.stringify(stixObject, null, 2);
  }

  /**
   * Convert alert to CSV row
   */
  toCSV(alert: any): string {
    const fields = [
      alert.alert_id,
      alert.timestamp,
      alert.event?.event_type || '',
      alert.event?.source_ip || '',
      alert.event?.destination_ip || '',
      alert.event?.source_port || '',
      alert.event?.destination_port || '',
      alert.event?.protocol || '',
      alert.event?.username || '',
      alert.threat_level || '',
      (alert.threat_score?.score || 0).toFixed(2),
      alert.priority || '',
      (alert._correlation_summary?.correlated_event_count || 0).toString(),
      (alert.behavior_analysis?.patterns?.length || 0).toString(),
      alert.summary || '',
    ];

    // Escape CSV fields
    return fields
      .map((field) => {
        const str = String(field || '');
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      })
      .join(',');
  }

  /**
   * Convert alert to Syslog (RFC 5424)
   */
  toSyslog(alert: any): string {
    const pri = this.mapSeverityToPriority(alert.threat_level);
    const timestamp = new Date(alert.timestamp).toISOString();
    const hostname = 'fusion-cell';
    const appName = 'cyber-ew-fusion';
    const procId = '-';
    const msgId = alert.alert_id;
    const msg = `[${alert.threat_level}] ${alert.summary} - Score: ${alert.threat_score?.score || 0}`;

    return `<${pri}> ${timestamp} ${hostname} ${appName} ${procId} ${msgId} - ${msg}`;
  }

  /**
   * Format as JSONL (newline-delimited JSON)
   */
  toJSONL(alert: any): string {
    return JSON.stringify(alert);
  }

  /**
   * Format alert in requested format
   */
  formatAlert(alert: any, format: 'jsonl' | 'cef' | 'stix' | 'csv' | 'syslog'): string {
    switch (format) {
      case 'cef':
        return this.toCEF(alert);
      case 'stix':
        return this.toSTIX(alert);
      case 'csv':
        return this.toCSV(alert);
      case 'syslog':
        return this.toSyslog(alert);
      case 'jsonl':
      default:
        return this.toJSONL(alert);
    }
  }

  /**
   * Generate CSV header row
   */
  getCSVHeader(): string {
    return [
      'alert_id',
      'timestamp',
      'event_type',
      'source_ip',
      'destination_ip',
      'source_port',
      'destination_port',
      'protocol',
      'username',
      'threat_level',
      'threat_score',
      'priority',
      'correlated_events',
      'behavior_patterns',
      'summary',
    ].join(',');
  }

  /**
   * Batch export multiple alerts
   */
  exportBatch(alerts: any[], format: 'jsonl' | 'cef' | 'stix' | 'csv' | 'syslog'): string {
    if (format === 'csv') {
      const header = this.getCSVHeader();
      const rows = alerts.map((a) => this.toCSV(a));
      return [header, ...rows].join('\n');
    }

    if (format === 'stix') {
      // Bundle multiple STIX objects
      const objects = alerts.map((a) => JSON.parse(this.toSTIX(a)));
      const bundle = {
        type: 'bundle',
        id: `bundle--${Date.now()}`,
        objects,
      };
      return JSON.stringify(bundle, null, 2);
    }

    return alerts.map((a) => this.formatAlert(a, format)).join('\n');
  }

  // ============ Helpers ============

  private mapSeverityToCEF(threatLevel: string): number {
    const severityMap: { [key: string]: number } = {
      Critical: 10,
      High: 8,
      Medium: 5,
      Low: 2,
    };
    return severityMap[threatLevel || 'Unknown'] || 5;
  }

  private mapSeverityToPriority(threatLevel: string): number {
    // Syslog priority = facility (16) * 8 + severity
    // Facility 16 = local0, severity: 0=emerg, 1=alert, 2=crit, 3=err, 4=warn, 5=notice, 6=info, 7=debug
    const severityMap: { [key: string]: number } = {
      Critical: 128 + 2, // local0.crit = 130
      High: 128 + 3, // local0.err = 131
      Medium: 128 + 4, // local0.warn = 132
      Low: 128 + 5, // local0.notice = 133
    };
    return severityMap[threatLevel || 'Unknown'] || 132;
  }

  private buildSTIXRefs(alert: any): string[] {
    const refs = [];
    if (alert.event?.source_ip) refs.push(`ipv4-addr--src`);
    if (alert.event?.destination_ip) refs.push(`ipv4-addr--dst`);
    if (alert.event?.username) refs.push(`user-account--${alert.event.username}`);
    if (alert.event?.source_port) refs.push(`network-traffic--src-port`);
    return refs;
  }

  private buildSTIXObservables(alert: any): { [key: string]: any } {
    const observables: { [key: string]: any } = {};

    if (alert.event?.source_ip) {
      observables['ipv4-addr--src'] = {
        type: 'ipv4-addr',
        value: alert.event.source_ip,
      };
    }

    if (alert.event?.destination_ip) {
      observables['ipv4-addr--dst'] = {
        type: 'ipv4-addr',
        value: alert.event.destination_ip,
      };
    }

    if (alert.event?.username) {
      observables[`user-account--${alert.event.username}`] = {
        type: 'user-account',
        user_id: alert.event.username,
      };
    }

    if (alert.event?.source_port || alert.event?.destination_port) {
      observables['network-traffic--src-port'] = {
        type: 'network-traffic',
        protocols: [alert.event?.protocol || 'tcp'].map((p) => p.toLowerCase()),
        src_ref: 'ipv4-addr--src',
        dst_ref: 'ipv4-addr--dst',
        src_port: alert.event?.source_port || 0,
        dst_port: alert.event?.destination_port || 0,
      };
    }

    return observables;
  }
}

export const outputEngine = new OutputEngine();
export default outputEngine;
