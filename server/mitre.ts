const mapping: { pattern: RegExp; techniques: string[]; description: string }[] = [
  { pattern: /credential|login attempt|ssh/i, techniques: ['T1110'], description: 'Credential Access' },
  { pattern: /rdp|remote desktop/i, techniques: ['T1021.001'], description: 'Remote Services: RDP' },
  { pattern: /smb|file share|remote file copy/i, techniques: ['T1021.002'], description: 'Remote Services: SMB' },
  { pattern: /exfil|data transfer|large data/i, techniques: ['T1041'], description: 'Exfiltration over C2' },
  { pattern: /ransomware|encrypt|ransom/i, techniques: ['T1486'], description: 'Data Encrypted for Impact' },
  { pattern: /lateral movement|lateral/i, techniques: ['T1021'], description: 'Lateral Movement' },
];

export function mapAlertToMitre(alert: any): { techniques: string[]; descriptions: string[] } {
  const text = (alert.summary || '') + ' ' + JSON.stringify(alert.event || {});
  const techniques = new Set<string>();
  const descriptions: string[] = [];

  for (const m of mapping) {
    if (m.pattern.test(text)) {
      m.techniques.forEach((t) => techniques.add(t));
      descriptions.push(m.description);
    }
  }

  return { techniques: Array.from(techniques), descriptions };
}

export default { mapAlertToMitre };
