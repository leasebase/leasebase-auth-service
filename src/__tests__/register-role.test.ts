/**
 * Tests for POST /internal/auth/register role handling.
 *
 * Verifies that:
 * - userType is accepted and validated
 * - custom:role is written to Cognito with the correct mapped value
 * - Org + User + Subscription bootstrap records are created for OWNER/PM
 * - TENANT signups skip org/user bootstrap
 * - Unknown userType values are rejected by schema validation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

// ── Hoisted mock functions (available inside vi.mock factories) ──────────────
const { mockCognitoSend, mockQuery, mockQueryOne } = vi.hoisted(() => {
  // Set env vars BEFORE modules are loaded (hoisted block runs first)
  process.env.COGNITO_CLIENT_ID = 'test-client-id';
  process.env.COGNITO_REGION = 'us-west-2';
  return {
    mockCognitoSend: vi.fn(),
    mockQuery: vi.fn(),
    mockQueryOne: vi.fn(),
  };
});

// ── Mock AWS SDK Cognito ─────────────────────────────────────────────────────
vi.mock('@aws-sdk/client-cognito-identity-provider', () => {
  return {
    CognitoIdentityProviderClient: vi.fn().mockImplementation(() => ({
      send: mockCognitoSend,
    })),
    InitiateAuthCommand: vi.fn(),
    SignUpCommand: vi.fn().mockImplementation((input: any) => ({ input })),
    ConfirmSignUpCommand: vi.fn(),
    ResendConfirmationCodeCommand: vi.fn(),
    AuthFlowType: { USER_PASSWORD_AUTH: 'USER_PASSWORD_AUTH' },
  };
});

// ── Mock service-common DB + auth ────────────────────────────────────────────
vi.mock('@leasebase/service-common', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...actual,
    query: mockQuery,
    queryOne: mockQueryOne,
    // Bypass real JWT verification in tests
    requireAuth: (_req: Request, _res: Response, next: NextFunction) => next(),
  };
});

// Env vars are set in the vi.hoisted block above (must run before module load).

import { authRouter } from '../routes/auth';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/internal/auth', authRouter);
  // Basic error handler
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.statusCode || err.status || 500;
    res.status(status).json({ error: { message: err.message, code: err.code || 'ERROR' } });
  });
  return app;
}

async function postRegister(app: ReturnType<typeof express>, body: Record<string, unknown>) {
  const server = app.listen(0);
  const addr = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${addr.port}/internal/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const responseBody = await res.json() as Record<string, unknown>;
    return { status: res.status, body: responseBody };
  } finally {
    server.close();
  }
}

const basePayload = {
  email: 'owner@test.com',
  password: 'SecurePass1!',
  firstName: 'Jane',
  lastName: 'Owner',
};

describe('POST /internal/auth/register — role handling', () => {
  beforeEach(() => {
    mockCognitoSend.mockReset();
    mockQuery.mockReset();
    mockQueryOne.mockReset();
  });

  // ── OWNER signup ─────────────────────────────────────────────────────────

  it('OWNER signup: writes custom:role=OWNER to Cognito and bootstraps Org+User+Subscription', async () => {
    const cognitoSub = 'cognito-sub-owner-123';
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: cognitoSub,
    });

    // Org creation returns org ID
    mockQuery
      .mockResolvedValueOnce([{ id: 'org-owner-1' }])  // INSERT Organization
      .mockResolvedValueOnce([])                         // INSERT User
      .mockResolvedValueOnce([]);                        // INSERT Subscription

    const app = buildApp();
    const { status, body } = await postRegister(app, { ...basePayload, userType: 'OWNER' });

    expect(status).toBe(201);
    expect(body.userSub).toBe(cognitoSub);

    // Verify Cognito SignUpCommand included custom:role=OWNER
    const signUpCall = mockCognitoSend.mock.calls[0][0];
    const attrs = signUpCall.input.UserAttributes;
    const roleAttr = attrs.find((a: any) => a.Name === 'custom:role');
    expect(roleAttr).toBeDefined();
    expect(roleAttr.Value).toBe('OWNER');

    // Verify DB bootstrap: 3 INSERT queries (Org, User, Subscription)
    expect(mockQuery).toHaveBeenCalledTimes(3);

    // Org INSERT uses LANDLORD type
    const orgInsertArgs = mockQuery.mock.calls[0];
    expect(orgInsertArgs[0]).toContain('INSERT INTO "Organization"');
    expect(orgInsertArgs[1]).toContain('LANDLORD');

    // User INSERT uses correct role and cognitoSub
    const userInsertArgs = mockQuery.mock.calls[1];
    expect(userInsertArgs[0]).toContain('INSERT INTO "User"');
    expect(userInsertArgs[1]).toContain(cognitoSub);
    expect(userInsertArgs[1]).toContain('OWNER');
  });

  // ── PROPERTY_MANAGER signup ──────────────────────────────────────────────

  it('PROPERTY_MANAGER signup: maps to ORG_ADMIN role and PM_COMPANY org', async () => {
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: 'cognito-sub-pm-456',
    });

    mockQuery
      .mockResolvedValueOnce([{ id: 'org-pm-1' }])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    const app = buildApp();
    const { status } = await postRegister(app, {
      ...basePayload,
      email: 'pm@test.com',
      userType: 'PROPERTY_MANAGER',
    });

    expect(status).toBe(201);

    // Cognito custom:role should be ORG_ADMIN
    const signUpCall = mockCognitoSend.mock.calls[0][0];
    const roleAttr = signUpCall.input.UserAttributes.find((a: any) => a.Name === 'custom:role');
    expect(roleAttr.Value).toBe('ORG_ADMIN');

    // Org type should be PM_COMPANY
    const orgInsertArgs = mockQuery.mock.calls[0];
    expect(orgInsertArgs[1]).toContain('PM_COMPANY');

    // User role should be ORG_ADMIN
    const userInsertArgs = mockQuery.mock.calls[1];
    expect(userInsertArgs[1]).toContain('ORG_ADMIN');
  });

  // ── TENANT signup ── Rejected ──────────────────────────────────────────────

  it('TENANT signup: rejected with 400', async () => {
    const app = buildApp();
    const { status, body } = await postRegister(app, {
      ...basePayload,
      email: 'tenant@test.com',
      userType: 'TENANT',
    });

    // TENANT is no longer an accepted userType — Zod validation rejects it.
    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockCognitoSend).not.toHaveBeenCalled();
  });

  // ── Validation ───────────────────────────────────────────────────────────

  it('rejects registration without userType', async () => {
    const app = buildApp();
    const { status } = await postRegister(app, basePayload);

    // Zod validation rejects missing userType — Cognito should NOT be called.
    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockCognitoSend).not.toHaveBeenCalled();
  });

  it('rejects registration with invalid userType', async () => {
    const app = buildApp();
    const { status } = await postRegister(app, {
      ...basePayload,
      userType: 'SUPER_ADMIN',
    });

    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockCognitoSend).not.toHaveBeenCalled();
  });

  // ── Bootstrap failure resilience ─────────────────────────────────────────

  it('OWNER signup succeeds even if DB bootstrap fails', async () => {
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: 'cognito-sub-owner-fail',
    });

    // Simulate DB failure
    mockQuery.mockRejectedValueOnce(new Error('DB connection failed'));

    const app = buildApp();
    const { status, body } = await postRegister(app, { ...basePayload, userType: 'OWNER' });

    // Registration should still succeed (Cognito user created)
    expect(status).toBe(201);
    expect(body.userSub).toBe('cognito-sub-owner-fail');
  });
});
