import { outputEngine } from '../server/output';

describe('Output Engine', () => {
  const exampleAlert = {
    alert_id: 'alt_test_001',
    timestamp: '2026-08-27T23:20:00.000Z',
    event: {
      event_id: 'evt_test_001',
      event_type: 'security_alert',
      source_ip: '192.168.1.100',
      destination_ip: '198.51.100.23',
      source_port: 54321,
      destination_port: 443,
      protocol: 'tcp',
      username: 'admin',
      severity: 'high',
    },
    threat_score: { score: 0.85, level: 'High', confidence: 0.9, sources: [] },
    threat_level: 'High',
    priority: 'P2',
    summary: 'Potential lateral movement detected',
    recommended_actions: ['Investigate', 'Quarantine'],
    _correlation_summary: { correlated_event_count: 3 },
    behavior_analysis: { patterns: [{ description: 'Anomalous login pattern' }] },
  };

  test('converts alert to CEF format', () => {
    const cef = outputEngine.toCEF(exampleAlert);
    expect(cef).toMatch(/^CEF:0\|CyberEW\|FusionCell\|1.0\|/);
    expect(cef).toContain('src=192.168.1.100');
    expect(cef).toContain('dst=198.51.100.23');
    expect(cef).toContain('severity=8');
  });

  test('converts alert to STIX format', () => {
    const stix = outputEngine.toSTIX(exampleAlert);
    const obj = JSON.parse(stix);
    expect(obj.type).toBe('observed-data');
    expect(obj.x_threat_score.score).toBe(0.85);
    expect(obj.x_threat_score.level).toBe('High');
  });

  test('converts alert to CSV format', () => {
    const csv = outputEngine.toCSV(exampleAlert);
    expect(csv).toContain('alt_test_001');
    expect(csv).toContain('192.168.1.100');
    expect(csv).toContain('High');
    expect(csv).toContain('0.85');
  });

  test('generates CSV header', () => {
    const header = outputEngine.getCSVHeader();
    expect(header).toContain('alert_id');
    expect(header).toContain('timestamp');
    expect(header).toContain('threat_level');
  });

  test('converts alert to Syslog format', () => {
    const syslog = outputEngine.toSyslog(exampleAlert);
    expect(syslog).toMatch(/^<\d+>/);
    expect(syslog).toContain('fusion-cell');
    expect(syslog).toContain('High');
  });

  test('converts alert to JSONL format', () => {
    const jsonl = outputEngine.toJSONL(exampleAlert);
    const parsed = JSON.parse(jsonl);
    expect(parsed.alert_id).toBe('alt_test_001');
    expect(parsed.threat_level).toBe('High');
  });

  test('exports batch as CSV with header', () => {
    const alerts = [exampleAlert, exampleAlert];
    const csv = outputEngine.exportBatch(alerts, 'csv');
    const lines = csv.split('\n');
    expect(lines.length).toBe(3); // header + 2 alerts
    expect(lines[0]).toContain('alert_id');
  });

  test('exports batch as STIX bundle', () => {
    const alerts = [exampleAlert, exampleAlert];
    const bundle = outputEngine.exportBatch(alerts, 'stix');
    const obj = JSON.parse(bundle);
    expect(obj.type).toBe('bundle');
    expect(obj.objects.length).toBe(2);
  });

  test('exports batch as JSONL (newline-separated)', () => {
    const alerts = [exampleAlert, exampleAlert];
    const jsonl = outputEngine.exportBatch(alerts, 'jsonl');
    const lines = jsonl.split('\n');
    expect(lines.length).toBe(2);
    lines.forEach((line) => {
      const obj = JSON.parse(line);
      expect(obj.alert_id).toBe('alt_test_001');
    });
  });

  test('handles alerts with missing fields gracefully', () => {
    const minimalAlert = { alert_id: 'alt_minimal', timestamp: '2026-08-27T23:20:00.000Z' };
    expect(() => outputEngine.toCEF(minimalAlert)).not.toThrow();
    expect(() => outputEngine.toSTIX(minimalAlert)).not.toThrow();
    expect(() => outputEngine.toCSV(minimalAlert)).not.toThrow();
  });

  test('formatAlert dispatches to correct formatter', () => {
    expect(outputEngine.formatAlert(exampleAlert, 'cef')).toMatch(/^CEF:0/);
    expect(() => JSON.parse(outputEngine.formatAlert(exampleAlert, 'stix'))).not.toThrow();
    expect(outputEngine.formatAlert(exampleAlert, 'csv')).toContain('192.168.1.100');
    expect(outputEngine.formatAlert(exampleAlert, 'syslog')).toMatch(/^<\d+>/);
    const jsonl = outputEngine.formatAlert(exampleAlert, 'jsonl');
    expect(() => JSON.parse(jsonl)).not.toThrow();
  });
});
