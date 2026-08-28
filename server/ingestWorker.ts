import fs from "fs";
import path from "path";

export function startFileWatcher(DATA_DIR: string) {
  if (process.env.NODE_ENV === 'test') {
    console.log('[ingestWorker] Test environment detected; file watcher disabled');
    return () => {};
  }

  const inputDir = path.join(DATA_DIR, "inputs", "live");
  const processedDir = path.join(inputDir, "processed");
  const outputsDir = path.join(DATA_DIR, "outputs");

  if (!fs.existsSync(inputDir)) fs.mkdirSync(inputDir, { recursive: true });
  if (!fs.existsSync(processedDir)) fs.mkdirSync(processedDir, { recursive: true });
  if (!fs.existsSync(outputsDir)) fs.mkdirSync(outputsDir, { recursive: true });

  const alertsPath = path.join(outputsDir, "alerts.jsonl");

  let running = true;
  console.log("[ingestWorker] Starting file watcher for", inputDir);

  async function processFile(fileName: string) {
    const filePath = path.join(inputDir, fileName);
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) return;

      const content = fs.readFileSync(filePath, "utf-8");
      let parsedCount = 0;
      const alertsToAppend: string[] = [];
      const lower = fileName.toLowerCase();

      // detect format by filename and content
      let format = 'suricata_eve';
      if (lower.includes('zeek') || (lower.endsWith('.tsv') && content.includes('\t'))) format = 'zeek_tsv';
      if (lower.includes('syslog') || lower.endsWith('.log')) format = 'syslog';
      if (lower.includes('windows') || lower.includes('winevent')) format = 'windows_event';

      if (lower.endsWith(".eve") || lower.endsWith(".jsonl") || lower.endsWith(".json")) {
        const lines = content.split("\n");
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const parsed = JSON.parse(line);
            parsedCount++;
            const { normalizeToAlert } = await import("./normalization");
            const norm = normalizeToAlert(parsed, parsed.System?.EventID ? 'windows_event' : 'suricata_eve', fileName);
            try {
              const { behaviorEngine } = await import("./behavior");
              const behResult = behaviorEngine.detectAnomalies(norm);
              norm.behavior_analysis = behResult;
            } catch (e) {}
            try {
              const { correlationEngine } = await import("./correlation");
              correlationEngine.addEvent(norm);
              norm._correlation_summary = correlationEngine.getCorrelatedSummary(norm);
            } catch (e) {}
            try {
              const { scoringEngine } = await import("./scoring");
              scoringEngine.scoreAlert(norm);
            } catch (e) {}
                        try { const { notifyWebhooks } = await import("./webhooks"); if (['High','Critical'].includes(norm.threat_level)) await notifyWebhooks(norm); } catch(e) {}
                        alertsToAppend.push(JSON.stringify(norm));
          } catch (err) {
            // skip malformed lines
          }
        }
      } else if (format === 'zeek_tsv' && (lower.includes('zeek') || lower.endsWith('.tsv'))) {
        // Zeek TSV format
        const lines = content.split("\n");
        const { normalizeToAlert } = await import("./normalization");
        for (const line of lines) {
          if (!line.trim() || line.startsWith('#')) continue;
          try {
            parsedCount++;
            const norm = normalizeToAlert(line, 'zeek_tsv', fileName);
            try {
              const { behaviorEngine } = await import("./behavior");
              const behResult = behaviorEngine.detectAnomalies(norm);
              norm.behavior_analysis = behResult;
            } catch (e) {}
            try {
              const { correlationEngine } = await import("./correlation");
              correlationEngine.addEvent(norm);
              norm._correlation_summary = correlationEngine.getCorrelatedSummary(norm);
            } catch (e) {}
            try {
              const { scoringEngine } = await import("./scoring");
              scoringEngine.scoreAlert(norm);
            } catch (e) {}
            try { const { notifyWebhooks } = await import("./webhooks"); if (['High','Critical'].includes(norm.threat_level)) await notifyWebhooks(norm); } catch(e) {}
            alertsToAppend.push(JSON.stringify(norm));
          } catch (err) {
            // skip
          }
        }
      } else if (format === 'syslog' && (lower.includes('syslog') || lower.endsWith('.log'))) {
        // Syslog format
        const lines = content.split("\n");
        const { normalizeToAlert } = await import("./normalization");
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            parsedCount++;
            const norm = normalizeToAlert(line, 'syslog', fileName);
            try {
              const { behaviorEngine } = await import("./behavior");
              const behResult = behaviorEngine.detectAnomalies(norm);
              norm.behavior_analysis = behResult;
            } catch (e) {}
            try {
              const { correlationEngine } = await import("./correlation");
              correlationEngine.addEvent(norm);
              norm._correlation_summary = correlationEngine.getCorrelatedSummary(norm);
            } catch (e) {}
            try {
              const { scoringEngine } = await import("./scoring");
              scoringEngine.scoreAlert(norm);
            } catch (e) {}
            try { const { notifyWebhooks } = await import("./webhooks"); if (['High','Critical'].includes(norm.threat_level)) await notifyWebhooks(norm); } catch(e) {}
            alertsToAppend.push(JSON.stringify(norm));
          } catch (err) {
            // skip
          }
        }
      }

      if (alertsToAppend.length > 0) {
        try {
          // buffered append using persistWriter
          const { persistWriter } = await import("./persistWriter");
          persistWriter.appendLines(alertsToAppend.join("\n"));
          console.log(`[ingestWorker] Appended ${alertsToAppend.length} alerts from ${fileName}`);
        } catch (e) {
          console.error("[ingestWorker] Error writing alerts.jsonl:", e);
        }
      } else {
        console.log(`[ingestWorker] No alerts generated from ${fileName} (parsed ${parsedCount} records)`);
      }

      // move processed file
      const dest = path.join(processedDir, `${Date.now()}_${fileName}`);
      try {
        fs.renameSync(filePath, dest);
      } catch (e) {
        console.warn(`[ingestWorker] Failed to move processed file ${fileName}:`, e.message);
      }
    } catch (err) {
      console.error(`[ingestWorker] Error processing file ${fileName}:`, err);
    }
  }

  // simple polling loop
  const interval = setInterval(() => {
    if (!running) return;
    try {
      const files = fs.readdirSync(inputDir).filter(f => f !== "processed");
      for (const f of files) {
        if (f.startsWith(".") || f.endsWith(".processing")) continue;
        processFile(f);
      }
    } catch (e) {
      // ignore directory read errors
    }
  }, 2000);

  return () => {
    running = false;
    clearInterval(interval);
    console.log("[ingestWorker] Stopped file watcher");
  };
}
