/**
 * Tests for GET /internal/auth/me route.
 *
 * We mock the requireAuth middleware (which depends on Cognito JWKS)
 * and test that the route returns the user profile from req.user.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

// Mock requireAuth from service-common to inject a fake user.
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
        role: 'ORG_ADMIN',
        name: 'Alice',
        scopes: ['api/read', 'api/write'],
      };
      next();
    },
  };
});

// Import AFTER mocking
import { authRouter } from '../routes/auth';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/internal/auth', authRouter);
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
  it('returns the authenticated user profile', async () => {
    const app = buildApp();
    const { status, body } = await request(app, 'GET', '/internal/auth/me');

    expect(status).toBe(200);
    expect(body).toEqual({
      id: 'user-abc',
      orgId: 'org-1',
      email: 'alice@example.com',
      name: 'Alice',
      role: 'ORG_ADMIN',
    });
  });
});
