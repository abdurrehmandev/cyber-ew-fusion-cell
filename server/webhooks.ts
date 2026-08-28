import fs from 'fs';
import path from 'path';

const WEBHOOKS_FILE = path.join(process.cwd(), 'data', 'state', 'webhooks.json');

function loadWebhooks(): string[] {
  try {
    if (!fs.existsSync(WEBHOOKS_FILE)) return [];
    const c = fs.readFileSync(WEBHOOKS_FILE, 'utf-8');
    const arr = JSON.parse(c);
    if (Array.isArray(arr)) return arr;
  } catch (e) {}
  return [];
}

export async function notifyWebhooks(alert: any) {
  const hooks = loadWebhooks();
  if (!hooks.length) return;
  for (const url of hooks) {
    try {
      // use global fetch (Node 18+)
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert }),
        timeout: 5000,
      });
    } catch (e) {
      // log and continue
      console.warn('[webhooks] Failed to notify', url, e?.message || e);
    }
  }
}

export default { notifyWebhooks };
