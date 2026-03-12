/**
 * Tests for the complete auth lifecycle endpoints:
 * register, confirm-email, resend-confirmation, login (unconfirmed),
 * forgot-password, and reset-password.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';

// ── Hoisted mocks ────────────────────────────────────────────────────────────
const { mockCognitoSend, mockQuery, mockQueryOne } = vi.hoisted(() => {
  process.env.COGNITO_CLIENT_ID = 'test-client-id';
  process.env.COGNITO_REGION = 'us-west-2';
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
  InitiateAuthCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  SignUpCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  ConfirmSignUpCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  ResendConfirmationCodeCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  ForgotPasswordCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  ConfirmForgotPasswordCommand: vi.fn().mockImplementation((input: any) => ({ input })),
  AdminCreateUserCommand: vi.fn(),
  AdminSetUserPasswordCommand: vi.fn(),
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

async function post(app: ReturnType<typeof express>, path: string, body: Record<string, unknown>) {
  const server = app.listen(0);
  const addr = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${addr.port}${path}`, {
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

describe('Auth lifecycle endpoints', () => {
  beforeEach(() => {
    mockCognitoSend.mockReset();
    mockQuery.mockReset();
    mockQueryOne.mockReset();
  });

  // ── 1. Register returns CONFIRM_SIGN_UP ────────────────────────────────────

  it('register returns nextStep=CONFIRM_SIGN_UP and normalized email', async () => {
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: 'sub-123',
    });
    // Org bootstrap
    mockQuery
      .mockResolvedValueOnce([{ id: 'org-1' }])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/register', {
      email: 'User@Example.COM',
      password: 'Password1!',
      firstName: 'Jane',
      lastName: 'Doe',
      userType: 'OWNER',
    });

    expect(status).toBe(201);
    expect(body.nextStep).toBe('CONFIRM_SIGN_UP');
    expect(body.email).toBe('user@example.com');
    expect(body.message).toContain('confirmation code');
  });

  // ── 1b. Register fails if DB bootstrap fails ──────────────────────────────

  it('register returns 500 if DB bootstrap fails (Cognito succeeds but DB insert fails)', async () => {
    mockCognitoSend.mockResolvedValueOnce({
      UserConfirmed: false,
      UserSub: 'sub-456',
    });
    // Org bootstrap fails (e.g., INSERT permission denied)
    mockQuery.mockRejectedValueOnce(new Error('permission denied for table Organization'));

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/register', {
      email: 'fail@example.com',
      password: 'Password1!',
      firstName: 'Fail',
      lastName: 'User',
      userType: 'OWNER',
    });

    // Bootstrap failure must surface as a server error, not a silent 201
    expect(status).toBe(500);
    expect((body as any).error).toBeDefined();
  });

  // ── 2. Confirm email success

  it('confirm-email returns success message', async () => {
    mockCognitoSend.mockResolvedValueOnce({});

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/confirm-email', {
      email: 'user@example.com',
      code: '123456',
    });

    expect(status).toBe(200);
    expect(body.message).toContain('confirmed');
  });

  // ── 3. Confirm email — incorrect code ──────────────────────────────────────

  it('confirm-email with incorrect code returns error', async () => {
    const err = new Error('Code mismatch');
    (err as any).name = 'CodeMismatchException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/confirm-email', {
      email: 'user@example.com',
      code: 'wrong',
    });

    expect(status).toBeGreaterThanOrEqual(400);
    expect((body as any).error.message).toContain('incorrect');
  });

  // ── 4. Confirm email — expired code ────────────────────────────────────────

  it('confirm-email with expired code returns error', async () => {
    const err = new Error('Expired');
    (err as any).name = 'ExpiredCodeException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/confirm-email', {
      email: 'user@example.com',
      code: '000000',
    });

    expect(status).toBeGreaterThanOrEqual(400);
    expect((body as any).error.message).toContain('expired');
  });

  // ── 5. Resend confirmation — neutral response ──────────────────────────────

  it('resend-confirmation returns neutral message even for non-existent user', async () => {
    const err = new Error('User not found');
    (err as any).name = 'UserNotFoundException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/resend-confirmation', {
      email: 'nobody@example.com',
    });

    // Should NOT return an error — returns 200 with neutral message
    expect(status).toBe(200);
    expect(body.message).toContain('If an account exists');
  });

  // ── 6. Login unconfirmed user ──────────────────────────────────────────────

  it('login with unconfirmed user returns USER_NOT_CONFIRMED with 403', async () => {
    const err = new Error('Not confirmed');
    (err as any).name = 'UserNotConfirmedException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/login', {
      email: 'user@example.com',
      password: 'Password1!',
    });

    expect(status).toBe(403);
    expect(body.code).toBe('USER_NOT_CONFIRMED');
    expect(body.nextStep).toBe('CONFIRM_SIGN_UP');
    expect(body.message).toContain('not been confirmed');
  });

  // ── 7. Forgot password — neutral response ──────────────────────────────────

  it('forgot-password returns neutral message even for non-existent user', async () => {
    const err = new Error('User not found');
    (err as any).name = 'UserNotFoundException';
    mockCognitoSend.mockRejectedValueOnce(err);

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/forgot-password', {
      email: 'nobody@example.com',
    });

    expect(status).toBe(200);
    expect(body.message).toContain('If an account exists');
  });

  // ── 8. Reset password — success ────────────────────────────────────────────

  it('reset-password returns success message', async () => {
    mockCognitoSend.mockResolvedValueOnce({});

    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/reset-password', {
      email: 'user@example.com',
      code: '123456',
      newPassword: 'NewPassword1!',
    });

    expect(status).toBe(200);
    expect(body.message).toContain('reset');
  });

  // ── 9. Reset password — validation failures ────────────────────────────────

  it('reset-password rejects weak password via Zod validation', async () => {
    const app = buildApp();
    const { status, body } = await post(app, '/internal/auth/reset-password', {
      email: 'user@example.com',
      code: '123456',
      newPassword: 'short', // too short, missing uppercase/number/special
    });

    // Zod validation should reject before Cognito is called
    expect(status).toBeGreaterThanOrEqual(400);
    expect(mockCognitoSend).not.toHaveBeenCalled();
  });
});
