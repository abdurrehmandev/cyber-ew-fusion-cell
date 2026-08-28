import request from 'supertest';
import app from '../server';

describe('API smoke tests', () => {
  test('GET /api/health returns ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
  });

  test('POST /api/ingest/raw accepts jsonl and returns parsed_records', async () => {
    const sample = '{"timestamp":"2026-08-27T23:20:00.000Z","src_ip":"192.168.1.55","dest_ip":"198.51.100.23","alert":{"signature":"Test Suricata signature"}}\n';
    const res = await request(app)
      .post('/api/ingest/raw')
      .send({ format: 'jsonl', content: sample, sensor_tag: 'test' })
      .set('Content-Type', 'application/json');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('parsed_records');
  });
});
