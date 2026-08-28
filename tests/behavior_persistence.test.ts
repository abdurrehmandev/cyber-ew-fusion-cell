import fs from 'fs';
import path from 'path';
import { BehaviorEngine } from '../server/behavior';

jest.setTimeout(15000);

describe('Behavior Engine Persistence', () => {
  const baseDir = path.join(process.cwd(), 'data_test_behavior');
  const stateDir = path.join(baseDir, 'state');
  const persistFile = path.join(stateDir, 'behavior_profiles.json');

  beforeAll(() => {
    // cleanup
    try { fs.rmSync(baseDir, { recursive: true, force: true }); } catch (e) {}
  });

  afterAll(() => {
    try { fs.rmSync(baseDir, { recursive: true, force: true }); } catch (e) {}
  });

  test('saves and loads profiles to disk', async () => {
    const eng = new BehaviorEngine(60, baseDir, 1); // persist every 1s

    // add events to create a profile
    for (let i = 0; i < 55; i++) {
      eng.addEvent({ event: { source_ip: '10.0.0.5' } });
    }

    // wait for persistence to run
    await new Promise((r) => setTimeout(r, 1500));

    // stop timer and ensure saved
    eng.stopPersistence();

    expect(fs.existsSync(persistFile)).toBe(true);

    const content = fs.readFileSync(persistFile, 'utf-8');
    const arr = JSON.parse(content);
    expect(Array.isArray(arr)).toBe(true);
    const profile = arr.find((p: any) => p.host === '10.0.0.5');
    expect(profile).toBeDefined();
    expect(profile.event_count).toBeGreaterThanOrEqual(55);
    // anomaly should be recorded at multiples of 50
    expect(profile.anomalies.length).toBeGreaterThanOrEqual(1);
  });
});
