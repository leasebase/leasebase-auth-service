import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';

// ── Hoisted mocks ──────────────────────────────────────────────────────────
const { mockQuery, mockQueryOne, mockCognitoSend } = vi.hoisted(() => {
  // Set env vars before any module-level reads (imports are hoisted)
  process.env.INTERNAL_SERVICE_KEY = 'test-service-key';
  process.env.COGNITO_USER_POOL_ID = 'us-west-2_TestPool';
  process.env.COGNITO_CLIENT_ID = 'test-client-id';
  return {
    mockQuery: vi.fn(),
    mockQueryOne: vi.fn(),
    mockCognitoSend: vi.fn(),
  };
});

vi.mock('@leasebase/service-common', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...mod,
    query: mockQuery,
    queryOne: mockQueryOne,
    // requireAuth not needed for internal create-tenant (uses service key auth)
  };
});

vi.mock('@aws-sdk/client-cognito-identity-provider', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@aws-sdk/client-cognito-identity-provider')>();
  return {
    ...mod,
    CognitoIdentityProviderClient: vi.fn().mockImplementation(() => ({
      send: mockCognitoSend,
    })),
  };
});

// ── Imports (after mocks) ──────────────────────────────────────────────────
import express from 'express';
import { authRouter } from '../routes/auth';

// ── Test helpers ───────────────────────────────────────────────────────────

function req(
  port: number,
  method: string,
  path: string,
  body?: any,
  headers?: Record<string, string>,
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const r = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data).toString() } : {}),
          ...headers,
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode!, body: JSON.parse(raw) });
          } catch {
            resolve({ status: res.statusCode!, body: raw });
          }
        });
      },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

// ── Server setup ───────────────────────────────────────────────────────────
let server: http.Server;
let port: number;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use('/auth', authRouter);
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.statusCode || 500).json({ error: { code: err.code, message: err.message } });
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      port = (server.address() as any).port;
      resolve();
    });
  });
});

afterAll(() => server?.close());
beforeEach(() => {
  mockQuery.mockReset();
  mockQueryOne.mockReset();
  mockCognitoSend.mockReset();
});

// ── Tests ──────────────────────────────────────────────────────────────────

describe('POST /auth/create-tenant — Internal service-to-service', () => {
  const validPayload = {
    email: 'newtenant@test.com',
    password: 'StrongPass1!',
    firstName: 'Jane',
    lastName: 'Doe',
  };

  const serviceKeyHeader = { 'x-internal-service-key': 'test-service-key' };

  it('creates Cognito user and returns cognitoSub', async () => {
    mockCognitoSend
      // AdminCreateUserCommand
      .mockResolvedValueOnce({
        User: { Attributes: [{ Name: 'sub', Value: 'cognito-sub-abc' }] },
      })
      // AdminSetUserPasswordCommand
      .mockResolvedValueOnce({});

    const r = await req(port, 'POST', '/auth/create-tenant', validPayload, serviceKeyHeader);
    expect(r.status).toBe(201);
    expect(r.body.cognitoSub).toBe('cognito-sub-abc');
  });

  it('does NOT create any database records', async () => {
    mockCognitoSend
      .mockResolvedValueOnce({
        User: { Attributes: [{ Name: 'sub', Value: 'cognito-sub-abc' }] },
      })
      .mockResolvedValueOnce({});

    await req(port, 'POST', '/auth/create-tenant', validPayload, serviceKeyHeader);
    expect(mockQuery).not.toHaveBeenCalled();
    expect(mockQueryOne).not.toHaveBeenCalled();
  });

  it('rejects when service key is missing', async () => {
    const r = await req(port, 'POST', '/auth/create-tenant', validPayload);
    expect(r.status).toBe(401);
  });

  it('rejects when service key is wrong', async () => {
    const r = await req(port, 'POST', '/auth/create-tenant', validPayload, {
      'x-internal-service-key': 'wrong-key',
    });
    expect(r.status).toBe(401);
  });

  it('returns 400 for existing username', async () => {
    const err = new Error('Username exists') as any;
    err.name = 'UsernameExistsException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const r = await req(port, 'POST', '/auth/create-tenant', validPayload, serviceKeyHeader);
    expect(r.status).toBe(400);
  });

  it('returns 400 for invalid password', async () => {
    const err = new Error('Invalid password') as any;
    err.name = 'InvalidPasswordException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const r = await req(port, 'POST', '/auth/create-tenant', validPayload, serviceKeyHeader);
    expect(r.status).toBe(400);
  });

  it('validates required fields', async () => {
    const r = await req(port, 'POST', '/auth/create-tenant', { email: 'a@b.com' }, serviceKeyHeader);
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});
