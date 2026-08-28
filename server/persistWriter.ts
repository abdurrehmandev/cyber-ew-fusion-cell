import fs from 'fs';
import path from 'path';

class PersistWriter {
  private filePath: string;
  private buffer: string[] = [];
  private timer: NodeJS.Timeout | null = null;
  private flushIntervalMs: number;
  private maxBatch: number;

  constructor(dataDir?: string, flushIntervalMs = 2000, maxBatch = 100) {
    const base = dataDir || path.join(process.cwd(), 'data');
    this.filePath = path.join(base, 'outputs', 'alerts.jsonl');
    this.flushIntervalMs = flushIntervalMs;
    this.maxBatch = maxBatch;

    try { fs.mkdirSync(path.dirname(this.filePath), { recursive: true }); } catch (e) {}

    if (process.env.NODE_ENV !== 'test') {
      this.timer = setInterval(() => this.flush(), this.flushIntervalMs);

      const saveAndExit = () => {
        this.flush();
        process.exit(0);
      };
      process.on('SIGINT', saveAndExit);
      process.on('SIGTERM', saveAndExit);
    }
  }

  appendLines(lines: string) {
    const split = lines.trim().split('\n').filter(l => l.trim());
    for (const l of split) this.buffer.push(l);
    if (this.buffer.length >= this.maxBatch) this.flush();
  }

  flush() {
    if (this.buffer.length === 0) return;
    try {
      const toWrite = '\n' + this.buffer.join('\n');
      const fd = fs.openSync(this.filePath, 'a');
      try {
        fs.writeSync(fd, toWrite, null, 'utf-8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      this.buffer = [];
    } catch (e) {
      // ignore flush errors
    }
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.flush();
  }
}

export const persistWriter = new PersistWriter();
export default persistWriter;
