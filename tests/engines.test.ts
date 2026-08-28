import { normalizeToAlert, ensureIsoTimestamp } from '../server/normalization';
import { correlationEngine } from '../server/correlation';
import { behaviorEngine } from '../server/behavior';
import { scoringEngine } from '../server/scoring';

describe('Normalization engine', () => {
  test('normalizeToAlert Suricata format', () => {
    const suricataEvent = {
      timestamp: '2026-08-27T23:20:00.000Z',
      src_ip: '192.168.1.55',
      dest_ip: '198.51.100.23',
      alert: { signature: 'Test signature' },
    };
    const result = normalizeToAlert(suricataEvent, 'suricata_eve');
    expect(result).toHaveProperty('alert_id');
    expect(result.event.source_ip).toBe('192.168.1.55');
    expect(result.event.destination_ip).toBe('198.51.100.23');
  });

  test('ensureIsoTimestamp handles valid and invalid inputs', () => {
    const iso = ensureIsoTimestamp('2026-08-27T23:20:00.000Z');
    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    const fallback = ensureIsoTimestamp(null);
    expect(fallback).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe('Correlation engine', () => {
  test('adds events and queries by IP', () => {
    const alert1 = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt1', source_ip: '192.168.1.55', destination_ip: '198.51.100.23' },
    };
    correlationEngine.addEvent(alert1);
    const results = correlationEngine.queryByIp('192.168.1.55');
    expect(results.length).toBeGreaterThan(0);
  });

  test('getCorrelatedSummary returns correct structure', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt_test', source_ip: '10.0.0.1', destination_ip: '10.0.0.2' },
    };
    const summary = correlationEngine.getCorrelatedSummary(alert);
    expect(summary).toHaveProperty('correlated_event_count');
    expect(summary).toHaveProperty('correlated_entities');
  });
});

describe('Behavior engine', () => {
  test('adds events and builds profiles', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt1', source_ip: '192.168.1.100' },
    };
    behaviorEngine.addEvent(alert);
    const profile = behaviorEngine.getProfile('192.168.1.100');
    expect(profile.event_count).toBeGreaterThan(0);
  });

  test('detectAnomalies returns patterns', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt_anom', source_ip: '10.0.0.5' },
    };
    const result = behaviorEngine.detectAnomalies(alert);
    expect(result).toHaveProperty('profile');
    expect(result).toHaveProperty('patterns');
  });
});

describe('Scoring engine', () => {
  test('scoreAlert computes threat_score correctly', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt_score', source_ip: '192.168.1.1', destination_ip: '8.8.8.8' },
      threat_score: { score: 0.6, level: 'Medium', confidence: 0.8, sources: [] },
      behavior_analysis: { patterns: [] },
    };
    const scored = scoringEngine.scoreAlert(alert);
    expect(scored.threat_score.score).toBeGreaterThanOrEqual(0);
    expect(scored.threat_score.score).toBeLessThanOrEqual(1);
    expect(scored.threat_level).toMatch(/Critical|High|Medium|Low/);
  });

  test('scoreAlert with correlation and behavior patterns', () => {
    const alert = {
      timestamp: new Date().toISOString(),
      event: { event_id: 'evt_complex' },
      threat_score: { score: 0.5, level: 'Medium', confidence: 0.7, sources: [] },
      _correlation_summary: { correlated_event_count: 5 },
      behavior_analysis: { patterns: [{ description: 'High volume' }, { description: 'Anomalous behavior' }] },
    };
    const scored = scoringEngine.scoreAlert(alert);
    expect(scored.threat_score.score).toBeGreaterThan(0.5); // should increase with correlation and behavior
  });
});
