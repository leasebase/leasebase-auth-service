import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';

const { mockQueryOne } = vi.hoisted(() => ({
  mockQueryOne: vi.fn(),
}));

vi.mock('@leasebase/service-common', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...mod,
    queryOne: mockQueryOne,
    requireAuth: (req: any, _res: any, next: any) => {
      req.user = { sub: 'cognito-sub', userId: 'user-123', orgId: 'org-1', email: 'a@b.com', role: 'OWNER', name: 'Test', scopes: [] };
      next();
    },
  };
});

import express from 'express';
import { settingsRouter } from '../routes/settings';

function req(
  port: number, method: string, path: string, body?: unknown,
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const r = http.request(
      { hostname: '127.0.0.1', port, path, method, headers: { 'Content-Type': 'application/json', ...(data ? { 'Content-Length': Buffer.byteLength(data).toString() } : {}) } },
      (res) => { let raw = ''; res.on('data', (c) => (raw += c)); res.on('end', () => { try { resolve({ status: res.statusCode!, body: JSON.parse(raw) }); } catch { resolve({ status: res.statusCode!, body: raw }); } }); },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

let server: http.Server;
let port: number;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use('/s', settingsRouter);
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.status || err.statusCode || 500).json({ error: { code: err.code, message: err.message } });
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => { port = (server.address() as any).port; resolve(); });
  });
});

afterAll(() => server?.close());
beforeEach(() => { mockQueryOne.mockReset(); });

describe('GET /settings', () => {
  it('returns defaults when no row exists', async () => {
    mockQueryOne.mockResolvedValueOnce(null);
    const { status, body } = await req(port, 'GET', '/s');
    expect(status).toBe(200);
    expect(body.data.theme_mode).toBe('system');
    expect(body.data.primary_color).toBeNull();
    expect(body.data.user_id).toBe('user-123');
  });

  it('returns existing settings', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123', theme_mode: 'dark', primary_color: '#ff0000' });
    const { status, body } = await req(port, 'GET', '/s');
    expect(status).toBe(200);
    expect(body.data.theme_mode).toBe('dark');
    expect(body.data.primary_color).toBe('#ff0000');
  });
});

describe('PUT /settings', () => {
  it('upserts settings (create)', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123', theme_mode: 'light' });
    const { status, body } = await req(port, 'PUT', '/s', { theme_mode: 'light' });
    expect(status).toBe(200);
    expect(body.data.theme_mode).toBe('light');
    const sql = mockQueryOne.mock.calls[0][0] as string;
    expect(sql).toContain('ON CONFLICT');
  });

  it('uses userId from JWT', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123' });
    await req(port, 'PUT', '/s', { theme_mode: 'dark' });
    const params = mockQueryOne.mock.calls[0][1] as unknown[];
    expect(params[0]).toBe('user-123');
  });

  it('rejects invalid theme_mode', async () => {
    const { status } = await req(port, 'PUT', '/s', { theme_mode: 'rainbow' });
    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockQueryOne).not.toHaveBeenCalled();
  });
});
