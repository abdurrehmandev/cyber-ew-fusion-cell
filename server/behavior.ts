import fs from 'fs';
import path from 'path';

type Profile = {
  host: string;
  event_count: number;
  last_seen: string;
  anomalies: string[];
};

export class BehaviorEngine {
  private profiles: Map<string, Profile> = new Map();
  private windowMs: number;
  private persistPath: string;
  private persistIntervalMs: number;
  private timer: NodeJS.Timeout | null = null;

  constructor(windowMinutes = 60, dataDir?: string, persistIntervalSeconds = 30) {
    this.windowMs = windowMinutes * 60 * 1000;
    const base = dataDir || path.join(process.cwd(), 'data');
    this.persistPath = path.join(base, 'state', 'behavior_profiles.json');
    this.persistIntervalMs = persistIntervalSeconds * 1000;

    // ensure directory
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
    } catch (e) {}

    // load existing profiles if present
    this.loadProfiles();

    // schedule periodic persistence (disabled during tests)
    if (process.env.NODE_ENV !== 'test') {
      this.timer = setInterval(() => {
        this.saveProfiles();
      }, this.persistIntervalMs);

      // graceful shutdown save
      const saveAndExit = () => {
        try {
          this.saveProfiles();
        } catch (e) {}
        process.exit(0);
      };

      process.on('SIGINT', saveAndExit);
      process.on('SIGTERM', saveAndExit);
    }
  }

  addEvent(alert: any) {
    try {
      const host = alert.event?.source_ip || alert.event?.destination_ip || 'unknown';
      const now = new Date().toISOString();
      const p = this.profiles.get(host) || { host, event_count: 0, last_seen: now, anomalies: [] };
      p.event_count += 1;
      p.last_seen = now;

      // Simple anomaly detection: burst of events increases anomalies
      if (p.event_count % 50 === 0) {
        p.anomalies.push(`High event volume: ${p.event_count}`);
      }

      // keep only recent anomalies
      if (p.anomalies.length > 10) p.anomalies = p.anomalies.slice(-10);
      this.profiles.set(host, p);
    } catch (e) {
      // ignore
    }
  }

  getProfile(host: string) {
    return this.profiles.get(host) || { host, event_count: 0, last_seen: new Date().toISOString(), anomalies: [] };
  }

  detectAnomalies(alert: any) {
    const host = alert.event?.source_ip || alert.event?.destination_ip || 'unknown';
    const profile = this.getProfile(host);
    const patterns: any[] = [];
    if (profile.event_count > 100) {
      patterns.push({ description: `High event rate (${profile.event_count})`, confidence: 0.9 });
    }
    if (profile.anomalies.length > 0) {
      for (const a of profile.anomalies.slice(-3)) patterns.push({ description: a, confidence: 0.7 });
    }
    return { profile, patterns };
  }

  saveProfiles() {
    try {
      const arr = Array.from(this.profiles.values());
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
      fs.writeFileSync(this.persistPath + '.tmp', JSON.stringify(arr, null, 2), 'utf-8');
      fs.renameSync(this.persistPath + '.tmp', this.persistPath);
      // fsync for durability
      const fd = fs.openSync(this.persistPath, 'r');
      try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    } catch (e) {
      // ignore persistence errors
    }
  }

  loadProfiles() {
    try {
      if (!fs.existsSync(this.persistPath)) return;
      const content = fs.readFileSync(this.persistPath, 'utf-8');
      const arr = JSON.parse(content) as Profile[];
      for (const p of arr) {
        this.profiles.set(p.host, p);
      }
    } catch (e) {
      // ignore load errors
    }
  }

  stopPersistence() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    try { this.saveProfiles(); } catch (e) {}
  }
}

export const behaviorEngine = new BehaviorEngine(60);
export default behaviorEngine;
