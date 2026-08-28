import fs from 'fs';
import path from 'path';

type IndexedEvent = { timestamp: string; event_id: string; alert_id?: string; source_ip?: string; destination_ip?: string; username?: string };

export class CorrelationEngine {
  private ipIndex: Map<string, IndexedEvent[]> = new Map();
  private userIndex: Map<string, IndexedEvent[]> = new Map();
  private windowMs: number;
  private persistPath: string;
  private persistIntervalMs: number;
  private timer: NodeJS.Timeout | null = null;

  constructor(windowMinutes = 10, dataDir?: string, persistIntervalSeconds = 30) {
    this.windowMs = windowMinutes * 60 * 1000;
    const base = dataDir || path.join(process.cwd(), 'data');
    this.persistPath = path.join(base, 'state', 'correlation_index.json');
    this.persistIntervalMs = persistIntervalSeconds * 1000;

    try { fs.mkdirSync(path.dirname(this.persistPath), { recursive: true }); } catch (e) {}

    this.loadIndex();

    if (process.env.NODE_ENV !== 'test') {
      this.timer = setInterval(() => {
        this.saveIndex();
      }, this.persistIntervalMs);

      const saveAndExit = () => {
        try { this.saveIndex(); } catch (e) {}
        process.exit(0);
      };
      process.on('SIGINT', saveAndExit);
      process.on('SIGTERM', saveAndExit);
    }
  }

  addEvent(alert: any) {
    try {
      const ts = new Date(alert.timestamp || alert.event?.timestamp || Date.now()).getTime();
      const e: IndexedEvent = {
        timestamp: new Date(ts).toISOString(),
        event_id: alert.event?.event_id || alert.event_id || `evt_${Date.now()}`,
        alert_id: alert.alert_id,
        source_ip: alert.event?.source_ip,
        destination_ip: alert.event?.destination_ip,
        username: alert.event?.username,
      };

      const now = Date.now();
      const evictBefore = now - this.windowMs;

      const addToIndex = (map: Map<string, IndexedEvent[]>, key?: string) => {
        if (!key) return;
        const arr = map.get(key) || [];
        arr.push(e);
        // evict old
        const kept = arr.filter(x => new Date(x.timestamp).getTime() >= evictBefore);
        map.set(key, kept);
      };

      addToIndex(this.ipIndex, e.source_ip);
      addToIndex(this.ipIndex, e.destination_ip);
      addToIndex(this.userIndex, e.username);
    } catch (err) {
      // ignore
    }
  }

  queryByIp(ip: string) {
    return this.ipIndex.get(ip) || [];
  }

  queryByUser(user: string) {
    return this.userIndex.get(user) || [];
  }

  getCorrelatedSummary(alert: any) {
    const src = alert.event?.source_ip;
    const dst = alert.event?.destination_ip;
    const user = alert.event?.username;
    const seen = new Set<string>();
    let count = 0;
    if (src) {
      const arr = this.queryByIp(src);
      arr.forEach(a => seen.add(a.event_id));
    }
    if (dst) {
      const arr = this.queryByIp(dst);
      arr.forEach(a => seen.add(a.event_id));
    }
    if (user) {
      const arr = this.queryByUser(user);
      arr.forEach(a => seen.add(a.event_id));
    }
    count = seen.size;
    return { correlated_event_count: count, correlated_entities: Array.from(seen).slice(0, 10) };
  }

  saveIndex() {
    try {
      const data = {
        ipIndex: Array.from(this.ipIndex.entries()),
        userIndex: Array.from(this.userIndex.entries()),
      };
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
      fs.writeFileSync(this.persistPath + '.tmp', JSON.stringify(data), 'utf-8');
      fs.renameSync(this.persistPath + '.tmp', this.persistPath);
      const fd = fs.openSync(this.persistPath, 'r');
      try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    } catch (e) {
      // ignore
    }
  }

  loadIndex() {
    try {
      if (!fs.existsSync(this.persistPath)) return;
      const content = fs.readFileSync(this.persistPath, 'utf-8');
      const data = JSON.parse(content) as any;
      if (data?.ipIndex) {
        for (const [k, arr] of data.ipIndex) {
          this.ipIndex.set(k, arr as IndexedEvent[]);
        }
      }
      if (data?.userIndex) {
        for (const [k, arr] of data.userIndex) {
          this.userIndex.set(k, arr as IndexedEvent[]);
        }
      }
    } catch (e) {
      // ignore
    }
  }

  stopPersistence() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    try { this.saveIndex(); } catch (e) {}
  }
}

export const correlationEngine = new CorrelationEngine(10);
export default correlationEngine;
