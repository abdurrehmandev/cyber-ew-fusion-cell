#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';

const dataDir = path.join(process.cwd(), 'data', 'inputs', 'live');

interface AttackScenario {
  name: string;
  events: any[];
}

// Credential Stuffing Attack Scenario
function generateCredentialStuffing(): AttackScenario {
  const timestamp = new Date();
  const targetHost = '192.168.1.50';
  const attackerHost = '203.0.113.45';
  const events = [];

  for (let i = 0; i < 50; i++) {
    const t = new Date(timestamp.getTime() + i * 1000);
    events.push({
      timestamp: t.toISOString(),
      src_ip: attackerHost,
      dest_ip: targetHost,
      dest_port: 22,
      proto: 'tcp',
      alert: { signature: `SSH login attempt ${i + 1}` },
      severity: i > 40 ? 'high' : 'medium',
    });
  }

  return { name: 'credential_stuffing', events };
}

// Lateral Movement Scenario
function generateLateralMovement(): AttackScenario {
  const timestamp = new Date();
  const compromised = '192.168.1.55';
  const target1 = '192.168.1.100';
  const target2 = '192.168.1.101';
  const events = [];

  for (const target of [target1, target2]) {
    events.push(
      {
        timestamp: new Date(timestamp.getTime()).toISOString(),
        src_ip: compromised,
        dest_ip: target,
        dest_port: 445,
        proto: 'tcp',
        alert: { signature: 'SMB connection attempt' },
        severity: 'high',
      },
      {
        timestamp: new Date(timestamp.getTime() + 2000).toISOString(),
        src_ip: compromised,
        dest_ip: target,
        dest_port: 3389,
        proto: 'tcp',
        alert: { signature: 'RDP connection attempt' },
        severity: 'high',
      }
    );
  }

  return { name: 'lateral_movement', events };
}

// Data Exfiltration Scenario
function generateDataExfiltration(): AttackScenario {
  const timestamp = new Date();
  const compromised = '192.168.1.55';
  const exfilTarget = '198.51.100.200';
  const events = [];

  for (let i = 0; i < 10; i++) {
    const t = new Date(timestamp.getTime() + i * 500);
    events.push({
      timestamp: t.toISOString(),
      src_ip: compromised,
      dest_ip: exfilTarget,
      dest_port: 443,
      proto: 'tcp',
      alert: { signature: `Large data transfer ${i + 1}` },
      severity: 'critical',
      event: { event_type: 'data_exfil' },
    });
  }

  return { name: 'data_exfiltration', events };
}

// Ransomware Propagation Scenario
function generateRansomwarePropagation(): AttackScenario {
  const timestamp = new Date();
  const compromised = '192.168.1.55';
  const events = [];

  const targets = ['192.168.1.60', '192.168.1.61', '192.168.1.62', '192.168.1.63'];

  for (const target of targets) {
    events.push({
      timestamp: new Date(timestamp.getTime() + Math.random() * 5000).toISOString(),
      src_ip: compromised,
      dest_ip: target,
      dest_port: 445,
      proto: 'tcp',
      alert: { signature: 'Ransomware propagation detected' },
      severity: 'critical',
    });
  }

  return { name: 'ransomware_propagation', events };
}

// Write scenario events to JSONL file
function writeScenario(scenario: AttackScenario): void {
  const filename = path.join(dataDir, `scenario_${scenario.name}_${Date.now()}.jsonl`);

  try {
    const lines = scenario.events.map((evt) => JSON.stringify(evt)).join('\n');
    fs.writeFileSync(filename, lines, 'utf8');
    console.log(`✓ Generated scenario: ${scenario.name} (${scenario.events.length} events) → ${filename}`);
  } catch (err) {
    console.error(`✗ Failed to write scenario ${scenario.name}:`, err);
  }
}

// Main
async function main(): Promise<void> {
  // Ensure input directory exists
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`✓ Created data directory: ${dataDir}`);
  }

  const scenarios = [
    generateCredentialStuffing(),
    generateLateralMovement(),
    generateDataExfiltration(),
    generateRansomwarePropagation(),
  ];

  console.log('Generating attack scenario telemetry...\n');
  for (const scenario of scenarios) {
    writeScenario(scenario);
  }

  console.log('\n✓ All scenarios generated. Ingest watcher will process them automatically.');
}

main().catch((err) => {
  console.error('Error generating scenarios:', err);
  process.exit(1);
});
