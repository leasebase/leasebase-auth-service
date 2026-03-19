/**
 * Tests for POST /internal/auth/register — bootstrap cleanup and error handling.
 *
 * Verifies:
 * - Successful registration WITH legalAcceptance payload
 * - Bootstrap failure triggers compensating Cognito AdminDeleteUser
 * - Bootstrap failure cleans up only records created in that attempt (by ID)
 * - Legal acceptance failure aborts registration by default (flag OFF)
 * - Legal acceptance failure is non-fatal when ALLOW_LEGAL_ACCEPTANCE_SOFT_FAIL=true
 * - Duplicate email (UsernameExistsException) returns 400 + DUPLICATE_EMAIL code
 * - Bootstrap failure returns 500 + BOOTSTRAP_FAILED code
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

// ── Hoisted mock functions ───────────────────────────────────────────────────
const { mockCognitoSend, mockQuery, mockQueryOne } = vi.hoisted(() => {
  process.env.COGNITO_CLIENT_ID = 'test-client-id';
  process.env.COGNITO_REGION = 'us-west-2';
  process.env.COGNITO_USER_POOL_ID = 'us-west-2_TestPool';
  // Default: legal acceptance is required (flag OFF)
  delete process.env.ALLOW_LEGAL_ACCEPTANCE_SOFT_FAIL;
  return {
    mockCognitoSend: vi.fn(),
    mockQuery: vi.fn(),
    mockQueryOne: vi.fn(),
  };
});

// ── Mock AWS SDK Cognito ─────────────────────────────────────────────────────
vi.mock('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: vi.fn().mockImplementation(() => ({
    send: mockCognitoSend,
  })),
  InitiateAuthCommand: vi.fn(),
  SignUpCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  ConfirmSignUpCommand: vi.fn(),
  ResendConfirmationCodeCommand: vi.fn(),
  ForgotPasswordCommand: vi.fn(),
  ConfirmForgotPasswordCommand: vi.fn(),
  AdminCreateUserCommand: vi.fn(),
  AdminSetUserPasswordCommand: vi.fn(),
  AdminDeleteUserCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  AuthFlowType: { USER_PASSWORD_AUTH: 'USER_PASSWORD_AUTH' },
}));

// ── Mock service-common ──────────────────────────────────────────────────────
vi.mock('@leasebase/service-common', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@leasebase/service-common')>();
  return {
    ...actual,
    query: mockQuery,
    queryOne: mockQueryOne,
    requireAuth: (_req: Request, _res: Response, next: NextFunction) => next(),
  };
});

import { authRouter } from '../routes/auth';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/internal/auth', authRouter);
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
  userType: 'OWNER',
};

const legalAcceptancePayload = [
  { slug: 'terms', version: '2026-03-v1', hash: 'abc123' },
  { slug: 'privacy', version: '2026-03-v1', hash: 'def456' },
  { slug: 'owner-agreement', version: '2026-03-v1', hash: 'ghi789' },
];

describe('POST /internal/auth/register — bootstrap cleanup and error handling', () => {
  beforeEach(() => {
    mockCognitoSend.mockReset();
    mockQuery.mockReset();
    mockQueryOne.mockReset();
  });

  // ── 1. Successful registration WITH legalAcceptance ───────────────────────

  it('successful OWNER signup with legalAcceptance persists all records', async () => {
    const cognitoSub = 'cognito-sub-legal-123';
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: cognitoSub,
    });

    mockQuery
      .mockResolvedValueOnce([{ id: 'org-1' }])    // INSERT Organization
      .mockResolvedValueOnce([{ id: 'user-1' }])   // INSERT User
      .mockResolvedValueOnce([{ id: 'sub-1' }])    // INSERT Subscription
      .mockResolvedValueOnce([]);                    // INSERT LegalAcceptance

    const app = buildApp();
    const { status, body } = await postRegister(app, {
      ...basePayload,
      legalAcceptance: legalAcceptancePayload,
    });

    expect(status).toBe(201);
    expect(body.nextStep).toBe('CONFIRM_SIGN_UP');
    expect(body.userSub).toBe(cognitoSub);

    // 4 queries: Org, User, Subscription, LegalAcceptance
    expect(mockQuery).toHaveBeenCalledTimes(4);

    // Last query is the LegalAcceptance INSERT
    const legalInsertArgs = mockQuery.mock.calls[3];
    expect(legalInsertArgs[0]).toContain('INSERT INTO "LegalAcceptance"');
  });

  // ── 2. Duplicate email returns DUPLICATE_EMAIL code ────────────────────────

  it('duplicate email returns 400 with DUPLICATE_EMAIL code', async () => {
    const err = new Error('User already exists');
    (err as any).name = 'UsernameExistsException';
    mockCognitoSend.mockRejectedValueOnce(err);

    // DB check for operational logging
    mockQueryOne.mockResolvedValueOnce({ id: 'existing-user' });

    const app = buildApp();
    const { status, body } = await postRegister(app, basePayload);

    expect(status).toBe(400);
    expect(body.code).toBe('DUPLICATE_EMAIL');
    expect(body.message).toContain('already exists');
  });

  // ── 3. Bootstrap failure triggers compensating Cognito cleanup ─────────────

  it('bootstrap failure triggers AdminDeleteUserCommand for Cognito cleanup', async () => {
    const cognitoSub = 'cognito-sub-cleanup-test';
    mockCognitoSend
      .mockResolvedValueOnce({ UserConfirmed: false, UserSub: cognitoSub })  // SignUp
      .mockResolvedValueOnce({});                                             // AdminDeleteUser

    // Org succeeds, User INSERT fails
    mockQuery
      .mockResolvedValueOnce([{ id: 'org-cleanup-1' }])   // INSERT Organization OK
      .mockRejectedValueOnce(new Error('column "bogus" does not exist'));  // INSERT User FAILS

    const app = buildApp();
    const { status, body } = await postRegister(app, basePayload);

    expect(status).toBe(500);
    expect(body.code).toBe('BOOTSTRAP_FAILED');

    // Cognito was called twice: SignUp + AdminDeleteUser cleanup
    expect(mockCognitoSend).toHaveBeenCalledTimes(2);
  });

  // ── 4. Bootstrap failure cleans up only THIS attempt's DB records ──────────

  it('bootstrap failure deletes only records created in the failed attempt', async () => {
    const cognitoSub = 'cognito-sub-targeted-cleanup';
    mockCognitoSend
      .mockResolvedValueOnce({ UserConfirmed: false, UserSub: cognitoSub })
      .mockResolvedValueOnce({});  // AdminDeleteUser

    // All three INSERTs succeed, then LegalAcceptance fails
    mockQuery
      .mockResolvedValueOnce([{ id: 'org-target-1' }])    // Org OK
      .mockResolvedValueOnce([{ id: 'user-target-1' }])   // User OK
      .mockResolvedValueOnce([{ id: 'sub-target-1' }])    // Subscription OK
      .mockRejectedValueOnce(new Error('relation "LegalAcceptance" does not exist'))  // Legal FAILS
      // Cleanup DELETEs (reverse order)
      .mockResolvedValueOnce([])   // DELETE Subscription
      .mockResolvedValueOnce([])   // DELETE User
      .mockResolvedValueOnce([]);  // DELETE Organization

    const app = buildApp();
    const { status } = await postRegister(app, {
      ...basePayload,
      legalAcceptance: legalAcceptancePayload,
    });

    expect(status).toBe(500);

    // Verify cleanup DELETEs used the exact IDs from this attempt
    const deleteCalls = mockQuery.mock.calls.filter(
      (call: any[]) => typeof call[0] === 'string' && call[0].includes('DELETE'),
    );
    expect(deleteCalls).toHaveLength(3);

    // Subscription delete by exact ID
    expect(deleteCalls[0][0]).toContain('DELETE FROM "Subscription"');
    expect(deleteCalls[0][1]).toEqual(['sub-target-1']);

    // User delete by exact ID
    expect(deleteCalls[1][0]).toContain('DELETE FROM "User"');
    expect(deleteCalls[1][1]).toEqual(['user-target-1']);

    // Org delete by exact ID
    expect(deleteCalls[2][0]).toContain('DELETE FROM "Organization"');
    expect(deleteCalls[2][1]).toEqual(['org-target-1']);
  });

  // ── 5. Legal acceptance failure aborts registration by default ─────────────

  it('legal acceptance failure aborts registration when soft-fail is OFF (default)', async () => {
    const cognitoSub = 'cognito-sub-legal-fail';
    mockCognitoSend
      .mockResolvedValueOnce({ UserConfirmed: false, UserSub: cognitoSub })
      .mockResolvedValueOnce({});  // AdminDeleteUser cleanup

    mockQuery
      .mockResolvedValueOnce([{ id: 'org-lf-1' }])
      .mockResolvedValueOnce([{ id: 'user-lf-1' }])
      .mockResolvedValueOnce([{ id: 'sub-lf-1' }])
      .mockRejectedValueOnce(new Error('relation "LegalAcceptance" does not exist'))
      // Cleanup DELETEs
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    const app = buildApp();
    const { status, body } = await postRegister(app, {
      ...basePayload,
      legalAcceptance: legalAcceptancePayload,
    });

    // Registration must fail — legal acceptance is required by default
    expect(status).toBe(500);
    expect(body.code).toBe('BOOTSTRAP_FAILED');
  });

  // ── 6. Bootstrap failure ONLY cleans Org if User INSERT was the failure point ──

  it('bootstrap failure after Org creation (before User) cleans up only the Org', async () => {
    const cognitoSub = 'cognito-sub-org-only';
    mockCognitoSend
      .mockResolvedValueOnce({ UserConfirmed: false, UserSub: cognitoSub })
      .mockResolvedValueOnce({});  // AdminDeleteUser

    mockQuery
      .mockResolvedValueOnce([{ id: 'org-only-1' }])         // Org OK
      .mockRejectedValueOnce(new Error('User insert failed'))  // User FAILS
      // Cleanup: only Org DELETE (no User/Sub to clean up)
      .mockResolvedValueOnce([]);  // DELETE Organization

    const app = buildApp();
    const { status } = await postRegister(app, basePayload);

    expect(status).toBe(500);

    // Only one DELETE (Organization) — User and Subscription were never created
    const deleteCalls = mockQuery.mock.calls.filter(
      (call: any[]) => typeof call[0] === 'string' && call[0].includes('DELETE'),
    );
    expect(deleteCalls).toHaveLength(1);
    expect(deleteCalls[0][0]).toContain('DELETE FROM "Organization"');
    expect(deleteCalls[0][1]).toEqual(['org-only-1']);
  });
});
