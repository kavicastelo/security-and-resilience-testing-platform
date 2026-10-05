import { describe, it, expect, afterAll } from 'vitest';
import { buildApp } from '../../apps/controller/src/app/index.js';
import { closeDatabase } from '../../apps/controller/src/services/db.js';

describe('Controller Health Integration Tests', () => {
  const app = buildApp({ disableLogging: true });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  it('GET /health returns healthy response with valid schema', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);

    expect(body).toHaveProperty('status');
    expect(['ok', 'degraded']).toContain(body.status);
    expect(body).toHaveProperty('version', '0.1.0');
    expect(body).toHaveProperty('timestamp');
    expect(body).toHaveProperty('uptime');
    expect(body).toHaveProperty('services');
    expect(body.services).toHaveProperty('database');
  });

  it('GET /api/v1/health returns versioned health response matching root endpoint', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/health',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);

    expect(['ok', 'degraded']).toContain(body.status);
    expect(body.version).toBe('0.1.0');
    expect(body.services).toBeDefined();
  });

  it('attaches correlation ID header to responses', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
      headers: {
        'x-correlation-id': 'test-trace-id-12345',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-correlation-id']).toBe('test-trace-id-12345');
  });
});
