/**
 * Tests for GET /internal/auth/me route.
 *
 * We mock the requireAuth middleware (which depends on Cognito JWKS)
 * and test that the route returns the user profile from req.user.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

// Hoisted mocks for DB layer
const { mockQueryOne, mockQuery } = vi.hoisted(() => ({
  mockQueryOne: vi.fn(),
  mockQuery: vi.fn(),
}));

// Mock requireAuth and queryOne from service-common.
vi.mock('@leasebase/service-common', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...actual,
    requireAuth: (req: Request, _res: Response, next: NextFunction) => {
      (req as any).user = {
        sub: 'user-abc',
        userId: 'user-abc',
        orgId: 'org-1',
        email: 'alice@example.com',
        role: 'OWNER',
        name: 'Alice',
        scopes: ['api/read', 'api/write'],
      };
      next();
    },
    queryOne: mockQueryOne,
    query: mockQuery,
  };
});

// Import AFTER mocking
import { authRouter } from '../routes/auth';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/internal/auth', authRouter);
  // Error handler so auth errors return JSON instead of HTML
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.statusCode || err.status || 500;
    res.status(status).json({ error: { message: err.message, code: err.code || 'ERROR' } });
  });
  return app;
}

// Lightweight supertest-like helper using Node fetch
async function request(app: ReturnType<typeof express>, method: string, path: string) {
  const server = app.listen(0);
  const addr = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${addr.port}${path}`, {
      method,
      headers: { Authorization: 'Bearer fake-token' },
    });
    const body = await res.json();
    return { status: res.status, body };
  } finally {
    server.close();
  }
}

describe('GET /internal/auth/me', () => {
  beforeEach(() => {
    mockQueryOne.mockReset();
    mockQuery.mockReset();
  });

  it('returns DB-backed profile when user exists in DB', async () => {
    // /me looks up user by cognitoSub — return DB user with authoritative role + orgId.
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-from-db',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'OWNER',
    });
    // /me now also queries user_organizations for the organizations array
    mockQuery.mockResolvedValueOnce([{ organization_id: 'org-from-db', role: 'OWNER' }]);

    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    expect(status).toBe(200);
    expect(body).toEqual({
      id: 'db-user-id',
      orgId: 'org-from-db',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'OWNER',
      organizations: [{ orgId: 'org-from-db', role: 'OWNER' }],
    });
  });

  it('returns 401 when DB user not found (fail closed)', async () => {
    mockQueryOne.mockResolvedValueOnce(null);

    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    // No DB user found → fail closed with 401
    expect(status).toBe(401);
    expect((body as any).error.message).toContain('User profile not found');
  });

  it('returns DB-backed role even when JWT-derived role differs', async () => {
    // The DB role (TENANT) should be returned, not the JWT-derived role (OWNER set in mock)
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id-2',
      organizationId: 'org-2',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'TENANT',
    });
    // user_organizations query
    mockQuery.mockResolvedValueOnce([{ organization_id: 'org-2', role: 'TENANT' }]);

    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    expect(status).toBe(200);
    expect((body as any).role).toBe('TENANT');
  });

  it('returns 200 with empty organizations when user_organizations query fails', async () => {
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id-3',
      organizationId: 'org-3',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'OWNER',
    });
    mockQuery.mockRejectedValueOnce(new Error('relation "public.user_organizations" does not exist'));

    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    expect(status).toBe(200);
    expect(body).toEqual({
      id: 'db-user-id-3',
      orgId: 'org-3',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'OWNER',
      organizations: [],
    });
  });

  it('returns 500 when DB query throws (not 401)', async () => {
    mockQueryOne.mockRejectedValueOnce(new Error('connection refused'));

    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    // DB error should surface as 500, not silently return 401
    expect(status).toBe(500);
    expect((body as any).error).toBeDefined();
  });
});
