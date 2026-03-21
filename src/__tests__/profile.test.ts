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
import { profileRouter } from '../routes/profile';

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
  app.use('/p', profileRouter);
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.status || err.statusCode || 500).json({ error: { code: err.code, message: err.message } });
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => { port = (server.address() as any).port; resolve(); });
  });
});

afterAll(() => server?.close());
beforeEach(() => { mockQueryOne.mockReset(); });

// ── Base User Profile ────────────────────────────────────────────────────────

describe('GET /profile (base)', () => {
  it('returns null when no profile exists', async () => {
    mockQueryOne.mockResolvedValueOnce(null);
    const { status, body } = await req(port, 'GET', '/p');
    expect(status).toBe(200);
    expect(body.data).toBeNull();
  });

  it('returns existing profile', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123', first_name: 'Alice', timezone: 'UTC' });
    const { status, body } = await req(port, 'GET', '/p');
    expect(status).toBe(200);
    expect(body.data.first_name).toBe('Alice');
  });
});

describe('PUT /profile (base)', () => {
  it('upserts a new profile (create)', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123', first_name: 'Bob', timezone: 'UTC' });
    const { status, body } = await req(port, 'PUT', '/p', { first_name: 'Bob' });
    expect(status).toBe(200);
    expect(body.data.first_name).toBe('Bob');
    expect(mockQueryOne).toHaveBeenCalledOnce();
    // Verify upsert SQL contains ON CONFLICT
    const sql = mockQueryOne.mock.calls[0][0] as string;
    expect(sql).toContain('ON CONFLICT');
  });

  it('passes userId from JWT, not from body', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123' });
    await req(port, 'PUT', '/p', { first_name: 'X' });
    const params = mockQueryOne.mock.calls[0][1] as unknown[];
    expect(params[0]).toBe('user-123'); // from req.user.userId
  });
});

// ── Owner Profile ────────────────────────────────────────────────────────────

describe('GET /profile/owner', () => {
  it('returns null when no owner profile exists', async () => {
    mockQueryOne.mockResolvedValueOnce(null);
    const { status, body } = await req(port, 'GET', '/p/owner');
    expect(status).toBe(200);
    expect(body.data).toBeNull();
  });
});

describe('PUT /profile/owner', () => {
  it('upserts owner profile', async () => {
    mockQueryOne.mockResolvedValueOnce({ user_id: 'user-123', company_name: 'Acme' });
    const { status, body } = await req(port, 'PUT', '/p/owner', { company_name: 'Acme' });
    expect(status).toBe(200);
    expect(body.data.company_name).toBe('Acme');
    const sql = mockQueryOne.mock.calls[0][0] as string;
    expect(sql).toContain('ON CONFLICT');
  });

  it('rejects invalid theme_mode', async () => {
    const { status } = await req(port, 'PUT', '/p/owner', { theme_mode: 'invalid' });
    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockQueryOne).not.toHaveBeenCalled();
  });
});
