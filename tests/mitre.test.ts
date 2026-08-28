import { mapAlertToMitre } from '../server/mitre';

describe('MITRE Mapping', () => {
  test('maps credential stuffing to T1110', () => {
    const alert = { summary: 'Multiple SSH login attempt detected', event: {} };
    const res = mapAlertToMitre(alert);
    expect(res.techniques).toContain('T1110');
  });

  test('maps ransomware keywords to T1486', () => {
    const alert = { summary: 'Detected ransomware encrypt activity', event: {} };
    const res = mapAlertToMitre(alert);
    expect(res.techniques).toContain('T1486');
  });

  test('maps data exfiltration to T1041', () => {
    const alert = { summary: 'Large data transfer to external host', event: {} };
    const res = mapAlertToMitre(alert);
    expect(res.techniques).toContain('T1041');
  });
});
