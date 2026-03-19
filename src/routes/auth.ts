import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
  ResendConfirmationCodeCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminDeleteUserCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  requireAuth,
  validateBody,
  logger,
  UnauthorizedError,
  ValidationError,
  type AuthenticatedRequest,
  verifyToken,
  getJwtConfig,
  UserRole,
  query,
  queryOne,
} from '@leasebase/service-common';

const router = Router();

const region = process.env.COGNITO_REGION || 'us-west-2';
// Accept both COGNITO_CLIENT_ID (canonical) and COGNITO_WEB_CLIENT_ID (legacy IaC name)
const clientId = process.env.COGNITO_CLIENT_ID || process.env.COGNITO_WEB_CLIENT_ID || '';
const userPoolId = process.env.COGNITO_USER_POOL_ID || '';
const cognitoClient = new CognitoIdentityProviderClient({ region });

// Shared secret for internal service-to-service calls
const INTERNAL_SERVICE_KEY = process.env.INTERNAL_SERVICE_KEY || '';

// DEV-only emergency flag: if true, legal acceptance persistence failure
// does NOT abort registration. Default OFF — legal acceptance is required.
const ALLOW_LEGAL_SOFT_FAIL = process.env.ALLOW_LEGAL_ACCEPTANCE_SOFT_FAIL === 'true';

// --- Schemas ---
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

/**
 * Allowed signup user types sent by the web registration form.
 * Only OWNER can self-register. Tenants are invited.
 */
const SIGNUP_USER_TYPES = ['OWNER'] as const;
type SignupUserType = (typeof SIGNUP_USER_TYPES)[number];

const legalAcceptanceItemSchema = z.object({
  slug: z.string().min(1),
  version: z.string().min(1),
  hash: z.string().optional(),
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  userType: z.enum(SIGNUP_USER_TYPES),
  legalAcceptance: z.array(legalAcceptanceItemSchema).optional(),
});

/** Map the UI signup userType to the internal application role. */
function mapUserTypeToRole(_userType: SignupUserType): string {
  return 'OWNER';
}

/** Map signup userType to the Organization type used in the DB. */
function mapUserTypeToOrgType(_userType: SignupUserType): string {
  return 'LANDLORD';
}

const confirmEmailSchema = z.object({
  email: z.string().email(),
  code: z.string().min(1),
});

const resendSchema = z.object({
  email: z.string().email(),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z.object({
  email: z.string().email(),
  code: z.string().min(1),
  newPassword: z
    .string()
    .min(8)
    .regex(/[A-Z]/, 'Password must contain an uppercase letter')
    .regex(/[a-z]/, 'Password must contain a lowercase letter')
    .regex(/\d/, 'Password must contain a number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain a special character'),
});

/** Normalize email: lowercase + trim. */
function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Extract the real client IP behind AWS ALB / reverse proxies.
 * Prefers the first (leftmost) IP from X-Forwarded-For, which is the
 * original client IP appended by each proxy hop.
 * Falls back to req.ip (which respects Express trust-proxy setting).
 */
function getClientIp(req: Request): string | undefined {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = (Array.isArray(xff) ? xff[0] : xff).split(',')[0];
    const trimmed = first.trim();
    if (trimmed) return trimmed;
  }
  return req.ip ?? undefined;
}

/**
 * Persist one LegalAcceptance row per document accepted.
 * Inserts all rows in a single multi-value INSERT for efficiency.
 */
async function persistLegalAcceptance(
  userId: string,
  items: Array<{ slug: string; version: string; hash?: string }>,
  source: string,
  ipAddress: string | undefined,
  userAgent: string | undefined,
): Promise<void> {
  if (!items || items.length === 0) return;

  // Build multi-row INSERT: (id, userId, documentSlug, documentVersion, documentHash, acceptedAt, source, ipAddress, userAgent)
  const values: any[] = [];
  const placeholders: string[] = [];
  let paramIndex = 1;

  for (const item of items) {
    placeholders.push(
      `(gen_random_uuid(), $${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3}, NOW(), $${paramIndex + 4}, $${paramIndex + 5}, $${paramIndex + 6})`,
    );
    values.push(userId, item.slug, item.version, item.hash ?? null, source, ipAddress ?? null, userAgent ?? null);
    paramIndex += 7;
  }

  await query(
    `INSERT INTO "LegalAcceptance" ("id", "userId", "documentSlug", "documentVersion", "documentHash", "acceptedAt", "source", "ipAddress", "userAgent")
     VALUES ${placeholders.join(', ')}
     ON CONFLICT ("userId", "documentSlug", "documentVersion", "source") DO NOTHING`,
    values,
  );
}

// --- POST /login ---
router.post('/login', validateBody(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, password } = req.body;
    const normalized = normalizeEmail(email);

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: clientId,
      AuthParameters: {
        USERNAME: normalized,
        PASSWORD: password,
      },
    });

    const response = await cognitoClient.send(command);

    // Cognito may return a challenge instead of tokens (e.g. when the user
    // was created via AdminCreateUser or had their password set without the
    // Permanent flag).  Detect this and return an actionable error.
    if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
      logger.warn(
        { email: normalized, challenge: response.ChallengeName },
        'Login blocked: user is in FORCE_CHANGE_PASSWORD state',
      );
      return res.status(403).json({
        code: 'NEW_PASSWORD_REQUIRED',
        message: 'You must reset your password before signing in. Please use "Forgot password?" to set a new one.',
        nextStep: 'RESET_PASSWORD',
      });
    }

    if (!response.AuthenticationResult) {
      // Some other unrecognized challenge
      logger.error(
        { email: normalized, challenge: response.ChallengeName },
        'Login failed: unrecognized Cognito challenge',
      );
      throw new UnauthorizedError('Authentication failed');
    }

    res.json({
      accessToken: response.AuthenticationResult.AccessToken,
      idToken: response.AuthenticationResult.IdToken,
      refreshToken: response.AuthenticationResult.RefreshToken,
      expiresIn: response.AuthenticationResult.ExpiresIn ?? 3600,
    });
  } catch (err: any) {
    if (err.name === 'NotAuthorizedException' || err.name === 'UserNotFoundException') {
      return next(new UnauthorizedError('Invalid email or password'));
    }
    if (err.name === 'UserNotConfirmedException') {
      return res.status(403).json({
        code: 'USER_NOT_CONFIRMED',
        message: 'Your email address has not been confirmed.',
        nextStep: 'CONFIRM_SIGN_UP',
      });
    }
    if (err.name === 'PasswordResetRequiredException') {
      return res.status(403).json({
        code: 'PASSWORD_RESET_REQUIRED',
        message: 'A password reset is required. Please use "Forgot password?" to set a new one.',
        nextStep: 'RESET_PASSWORD',
      });
    }
    next(err);
  }
});

// --- POST /register ---
router.post('/register', validateBody(registerSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, password, firstName, lastName, userType, legalAcceptance } = req.body as z.infer<typeof registerSchema>;
    const normalized = normalizeEmail(email);

    // Double-guard: reject tenant self-registration even if Zod validation is bypassed.
    if ((userType as unknown as string).toUpperCase() === 'TENANT') {
      throw new ValidationError('Tenants must be invited by a property owner or manager.');
    }

    const appRole = mapUserTypeToRole(userType);

    // ── 1. Create user in Cognito with custom:role attribute ──────────
    const command = new SignUpCommand({
      ClientId: clientId,
      Username: normalized,
      Password: password,
      UserAttributes: [
        { Name: 'email', Value: normalized },
        { Name: 'given_name', Value: firstName },
        { Name: 'family_name', Value: lastName },
        { Name: 'custom:role', Value: appRole },
      ],
    });

    const response = await cognitoClient.send(command);
    const cognitoSub = response.UserSub ?? '';

    // ── 2. Bootstrap Org + User + Subscription for OWNER / PM ────────
    // Tenant org/user records are created when a PM invites the tenant,
    // not during self-registration.
    if ((userType as unknown as string) !== 'TENANT' && cognitoSub) {
      // Track IDs created in this attempt for targeted cleanup on failure.
      let createdOrgId: string | undefined;
      let createdUserId: string | undefined;
      let createdSubscriptionId: string | undefined;

      try {
        const orgType = mapUserTypeToOrgType(userType);
        const fullName = `${firstName} ${lastName}`.trim();

        // Create organization
        const orgRows = await query<{ id: string }>(
          `INSERT INTO "Organization" ("id", "type", "name", "plan", "createdAt", "updatedAt")
           VALUES (gen_random_uuid(), $1, $2, 'basic', NOW(), NOW())
           RETURNING "id"`,
          [orgType, `${fullName}'s Organization`],
        );
        createdOrgId = orgRows[0]?.id;

        if (createdOrgId) {
          // Create user with correct role and cognitoSub
          const userRows = await query<{ id: string }>(
            `INSERT INTO "User" ("id", "organizationId", "email", "name", "cognitoSub", "role", "status", "createdAt", "updatedAt")
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'ACTIVE', NOW(), NOW())
             RETURNING "id"`,
            [createdOrgId, normalized, fullName, cognitoSub, appRole],
          );
          createdUserId = userRows[0]?.id;

          // Create subscription (basic plan)
          const subRows = await query<{ id: string }>(
            `INSERT INTO "Subscription" ("id", "organizationId", "plan", "unitCount", "status", "createdAt", "updatedAt")
             VALUES (gen_random_uuid(), $1, 'basic', 0, 'ACTIVE', NOW(), NOW())
             RETURNING "id"`,
            [createdOrgId],
          );
          createdSubscriptionId = subRows[0]?.id;

          // Persist legal acceptance rows (one per document)
          if (legalAcceptance && legalAcceptance.length > 0 && createdUserId) {
            try {
              await persistLegalAcceptance(
                createdUserId,
                legalAcceptance,
                'owner-signup',
                getClientIp(req),
                req.headers['user-agent'] as string | undefined,
              );
            } catch (legalErr: any) {
              // Legal acceptance INSERT failed (e.g. table missing, constraint error).
              if (ALLOW_LEGAL_SOFT_FAIL) {
                // Guarded DEV-only fallback: log warning but allow registration to proceed.
                logger.warn(
                  {
                    err: legalErr,
                    email: normalized,
                    cognitoSub,
                    userId: createdUserId,
                    phase: 'register.legal-acceptance',
                    softFail: true,
                    errorMessage: legalErr?.message,
                  },
                  'LegalAcceptance persistence failed (soft-fail enabled) — registration will proceed without legal acceptance records',
                );
              } else {
                // Default: legal acceptance is required — rethrow to trigger full cleanup.
                throw legalErr;
              }
            }
          }

          logger.info(
            { email, userType, appRole, orgId: createdOrgId, cognitoSub, legalDocsAccepted: legalAcceptance?.length ?? 0 },
            'Registration bootstrap: created Organization + User + Subscription + LegalAcceptance',
          );
        }
      } catch (bootstrapErr: any) {
        // ── Compensating cleanup: undo Cognito + partial DB records ────
        // Without cleanup, the orphaned Cognito user blocks re-registration
        // and partial DB records leave the system in an inconsistent state.
        logger.error(
          {
            err: bootstrapErr,
            email: normalized,
            userType,
            cognitoSub,
            createdOrgId,
            createdUserId,
            createdSubscriptionId,
            phase: 'register.bootstrap',
            errorClass: bootstrapErr?.constructor?.name,
            errorMessage: bootstrapErr?.message,
          },
          'Registration bootstrap FAILED — starting compensating cleanup',
        );

        // 1. Delete partial DB records (reverse order of creation)
        try {
          if (createdSubscriptionId) {
            await query(`DELETE FROM "Subscription" WHERE "id" = $1`, [createdSubscriptionId]);
          }
          if (createdUserId) {
            await query(`DELETE FROM "User" WHERE "id" = $1`, [createdUserId]);
          }
          if (createdOrgId) {
            await query(`DELETE FROM "Organization" WHERE "id" = $1`, [createdOrgId]);
          }
          logger.info(
            { email: normalized, cognitoSub, createdOrgId, createdUserId, createdSubscriptionId },
            'Compensating DB cleanup succeeded — partial records removed',
          );
        } catch (dbCleanupErr) {
          logger.error(
            { err: dbCleanupErr, email: normalized, cognitoSub, createdOrgId, createdUserId, createdSubscriptionId },
            'CRITICAL: Compensating DB cleanup FAILED — orphaned DB records may remain',
          );
        }

        // 2. Delete the orphaned Cognito user so the email can be re-registered
        if (userPoolId) {
          try {
            await cognitoClient.send(new AdminDeleteUserCommand({
              UserPoolId: userPoolId,
              Username: normalized,
            }));
            logger.info({ email: normalized, cognitoSub }, 'Compensating Cognito delete succeeded — user can re-register');
          } catch (cognitoCleanupErr: any) {
            if (cognitoCleanupErr.name === 'UserNotFoundException') {
              logger.warn({ email: normalized }, 'Cognito user already absent during cleanup');
            } else {
              logger.error(
                { err: cognitoCleanupErr, email: normalized, cognitoSub },
                'CRITICAL: Compensating Cognito delete FAILED — orphaned Cognito user remains, manual remediation required',
              );
            }
          }
        } else {
          logger.error(
            { email: normalized, cognitoSub },
            'Cannot clean up Cognito user — COGNITO_USER_POOL_ID is not configured',
          );
        }

        // Surface a structured error for the frontend
        const surfaceErr = new Error(
          'Account creation failed. Please try again.',
        );
        (surfaceErr as any).statusCode = 500;
        (surfaceErr as any).code = 'BOOTSTRAP_FAILED';
        throw surfaceErr;
      }
    }

    res.status(201).json({
      message: 'Account created. Please check your email for a confirmation code.',
      nextStep: 'CONFIRM_SIGN_UP',
      email: normalized,
      userConfirmed: response.UserConfirmed ?? false,
      userSub: cognitoSub,
    });
  } catch (err: any) {
    if (err.name === 'UsernameExistsException') {
      // Log which store(s) contain the duplicate for operational debugging.
      const normalized = normalizeEmail(req.body.email);
      let dbExists = false;
      try {
        const dbUser = await queryOne<{ id: string }>(
          `SELECT "id" FROM "User" WHERE LOWER("email") = $1`,
          [normalized],
        );
        dbExists = !!dbUser;
      } catch (dbErr) {
        logger.warn({ err: dbErr, email: normalized }, 'register: failed to check DB for duplicate (Cognito already rejected)');
      }

      logger.warn(
        { email: normalized, cognitoDuplicate: true, dbDuplicate: dbExists },
        `Registration blocked: duplicate user — Cognito=YES, DB=${dbExists ? 'YES' : 'NO'}`,
      );

      return res.status(400).json({
        code: 'DUPLICATE_EMAIL',
        error: { message: 'An account with this email already exists', code: 'DUPLICATE_EMAIL' },
        message: 'An account with this email already exists',
      });
    }
    if (err.name === 'InvalidPasswordException') {
      return next(new ValidationError('Password does not meet requirements'));
    }
    // Bootstrap failures carry a structured code for the frontend.
    if (err.code === 'BOOTSTRAP_FAILED') {
      return res.status(500).json({
        code: 'BOOTSTRAP_FAILED',
        error: { message: err.message, code: 'BOOTSTRAP_FAILED' },
        message: err.message,
      });
    }
    next(err);
  }
});

// --- POST /confirm-email ---
router.post('/confirm-email', validateBody(confirmEmailSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, code } = req.body;
    const normalized = normalizeEmail(email);

    await cognitoClient.send(new ConfirmSignUpCommand({
      ClientId: clientId,
      Username: normalized,
      ConfirmationCode: code,
    }));

    res.json({ message: 'Your email has been confirmed. You can now sign in.' });
  } catch (err: any) {
    if (err.name === 'CodeMismatchException') {
      return next(new ValidationError('The confirmation code is incorrect.'));
    }
    if (err.name === 'ExpiredCodeException') {
      return next(new ValidationError('The confirmation code has expired.'));
    }
    if (err.name === 'TooManyRequestsException') {
      return next(new ValidationError('Too many attempts. Please wait and try again.'));
    }
    next(err);
  }
});

// --- POST /resend-confirmation ---
router.post('/resend-confirmation', validateBody(resendSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const normalized = normalizeEmail(req.body.email);

    await cognitoClient.send(new ResendConfirmationCodeCommand({
      ClientId: clientId,
      Username: normalized,
    }));

    // Always return neutral response — do not reveal whether account exists.
    res.json({ message: 'If an account exists and is awaiting confirmation, a new code has been sent.' });
  } catch (err: any) {
    // Swallow UserNotFoundException to prevent account enumeration.
    if (err.name === 'UserNotFoundException') {
      res.json({ message: 'If an account exists and is awaiting confirmation, a new code has been sent.' });
      return;
    }
    next(err);
  }
});

// --- POST /forgot-password ---
router.post('/forgot-password', validateBody(forgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const normalized = normalizeEmail(req.body.email);

    await cognitoClient.send(new ForgotPasswordCommand({
      ClientId: clientId,
      Username: normalized,
    }));

    // Always return neutral response — do not reveal whether account exists.
    res.json({ message: 'If an account exists for this email, a reset code has been sent.' });
  } catch (err: any) {
    // Swallow UserNotFoundException to prevent account enumeration.
    if (err.name === 'UserNotFoundException') {
      res.json({ message: 'If an account exists for this email, a reset code has been sent.' });
      return;
    }
    if (err.name === 'TooManyRequestsException') {
      return next(new ValidationError('Too many attempts. Please wait and try again.'));
    }
    next(err);
  }
});

// --- POST /reset-password ---
router.post('/reset-password', validateBody(resetPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, code, newPassword } = req.body as z.infer<typeof resetPasswordSchema>;
    const normalized = normalizeEmail(email);

    await cognitoClient.send(new ConfirmForgotPasswordCommand({
      ClientId: clientId,
      Username: normalized,
      ConfirmationCode: code,
      Password: newPassword,
    }));

    res.json({ message: 'Your password has been reset. You can now sign in.' });
  } catch (err: any) {
    if (err.name === 'CodeMismatchException') {
      return next(new ValidationError('The reset code is incorrect.'));
    }
    if (err.name === 'ExpiredCodeException') {
      return next(new ValidationError('The reset code has expired.'));
    }
    if (err.name === 'InvalidPasswordException') {
      return next(new ValidationError('Password does not meet requirements.'));
    }
    if (err.name === 'TooManyRequestsException') {
      return next(new ValidationError('Too many attempts. Please wait and try again.'));
    }
    next(err);
  }
});

// --- GET /me ---
// requireAuth is fail-closed: rejects if JWT lacks custom:role.
// After auth, we look up the DB-backed profile for the authoritative role,
// orgId, and display name (Cognito access tokens lack these claims).
router.get('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    // In dev-bypass mode the role is set correctly from the header — skip DB.
    if (user.sub !== 'dev-bypass') {
      // Look up the user’s authoritative profile from the DB.
      // We fetch organizationId here because Cognito access tokens do NOT
      // carry custom:orgId — the JWT-derived user.orgId is usually empty.
      const dbUser = await queryOne<{ id: string; organizationId: string; email: string; name: string; role: string }>(
        `SELECT "id", "organizationId", "email", "name", "role" FROM "User" WHERE "cognitoSub" = $1`,
        [user.sub],
      );

      if (dbUser) {
        // Fetch all org memberships for multi-lease context switching.
        // Fail-open: if user_organizations is unavailable (e.g. migration
        // drift), still return /me with an empty organizations array.
        let organizations: Array<{ orgId: string; role: string }> = [];
        try {
          const orgRows = await query<{ organization_id: string; role: string }>(
            `SELECT organization_id, role FROM public.user_organizations WHERE user_id = $1`,
            [dbUser.id],
          );
          organizations = orgRows.map((r) => ({ orgId: r.organization_id, role: r.role }));
        } catch (orgErr) {
          logger.warn(
            { err: orgErr, userId: dbUser.id },
            '/me: user_organizations query failed — returning empty organizations',
          );
        }

        res.json({
          id: dbUser.id,
          orgId: dbUser.organizationId,
          email: dbUser.email,
          name: dbUser.name,
          role: dbUser.role,
          organizations,
        });
        return;
      }

      // No DB user found — fail closed.
      // Return 401 so the client clears the session.
      logger.warn(
        {
          sub: user.sub,
          email: user.email,
          jwtRole: user.role,
          hint: 'Cognito user exists but no DB User row. '
            + 'Likely cause: registration DB bootstrap failed silently. '
            + 'Run the backfill script or re-register.',
        },
        '/me: no DB user found for cognitoSub — failing closed',
      );
      throw new UnauthorizedError('User profile not found. Please contact support.');
    }

    // This branch only serves dev-bypass mode where the role is set correctly.
    res.json({
      id: user.userId,
      orgId: user.orgId,
      email: user.email,
      name: user.name,
      role: user.role,
    });
  } catch (err) {
    next(err);
  }
});

// --- GET /config ---
router.get('/config', (_req: Request, res: Response) => {
  const config = getJwtConfig();
  const issuer = config.userPoolId
    ? `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`
    : '';

  res.json({
    region: config.region,
    userPoolId: config.userPoolId,
    clientId: config.clientId,
    issuer,
    jwksUri: issuer ? `${issuer}/.well-known/jwks.json` : '',
  });
});

// --- POST /create-tenant (internal, service-to-service) ---
// Creates a Cognito user + canonical public."User" row for an invited tenant.
// Protected by X-Internal-Service-Key header.
const createTenantSchema = z.object({
  email: z.string().email(),
  // Password is optional: existing users (multi-lease) already have credentials.
  password: z.string().min(8).optional(),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  organizationId: z.string().uuid(),
  legalAcceptance: z.array(legalAcceptanceItemSchema).optional(),
});

/**
/**
 * POST /create-tenant — Internal service-to-service endpoint.
 *
 * Creates the full tenant identity:
 *   1. Cognito user (admin-created, permanent password)
 *   2. Canonical public."User" row (role='TENANT')
 *   3. user_organizations membership row
 *
 * **Multi-lease support**: If a User with this email already exists
 * (e.g. invited to a different org), we REUSE the existing Cognito
 * user + User row and only add a `user_organizations` entry for the
 * new org. The caller receives `existingUser: true` so it knows
 * the password field was ignored.
 *
 * auth-service is the sole owner of public."User" writes.
 * The calling service (tenant-service) is responsible for domain records
 * (TenantProfile, leases, unit status) but NOT identity records.
 */
router.post('/create-tenant', validateBody(createTenantSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Verify internal service key
    const serviceKey = req.headers['x-internal-service-key'] as string | undefined;
    if (!INTERNAL_SERVICE_KEY || !serviceKey || serviceKey !== INTERNAL_SERVICE_KEY) {
      throw new UnauthorizedError('Invalid or missing internal service key');
    }

    if (!userPoolId) {
      throw new ValidationError('Cognito user pool ID is not configured');
    }

    const { email, password, firstName, lastName, organizationId, legalAcceptance } = req.body as z.infer<typeof createTenantSchema>;
    const appRole = 'TENANT';
    const fullName = `${firstName} ${lastName}`.trim();

    // ── Multi-lease check: does a User with this email already exist? ────
    const existingUser = await queryOne<{ id: string; cognitoSub: string }>(
      `SELECT "id", "cognitoSub" FROM "User" WHERE LOWER("email") = LOWER($1)`,
      [email],
    );

    if (existingUser) {
      // Reuse the existing identity — just ensure the org membership exists.
      await query(
        `INSERT INTO public.user_organizations (user_id, organization_id, role, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (user_id, organization_id) DO NOTHING`,
        [existingUser.id, organizationId, appRole],
      );

      logger.info(
        { email, userId: existingUser.id, cognitoSub: existingUser.cognitoSub, organizationId },
        'Existing user linked to new org via user_organizations (multi-lease)',
      );

      return res.status(200).json({
        cognitoSub: existingUser.cognitoSub,
        userId: existingUser.id,
        existingUser: true,
      });
    }

    // ── New user: create Cognito identity + User row ─────────────────────

    // Password is required for new users — existing users skip this path above.
    if (!password) {
      throw new ValidationError('Password is required for new tenant accounts');
    }

    // 1. Create Cognito user (admin-initiated, suppress welcome email)
    const createCommand = new AdminCreateUserCommand({
      UserPoolId: userPoolId,
      Username: email,
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'email_verified', Value: 'true' },
        { Name: 'given_name', Value: firstName },
        { Name: 'family_name', Value: lastName },
        { Name: 'custom:role', Value: appRole },
      ],
      MessageAction: 'SUPPRESS',
    });

    const createResponse = await cognitoClient.send(createCommand);
    const cognitoSub = createResponse.User?.Attributes?.find(a => a.Name === 'sub')?.Value ?? '';

    if (!cognitoSub) {
      throw new ValidationError('Failed to create Cognito user — no sub returned');
    }

    // 2. Set permanent password (admin-created users start with FORCE_CHANGE_PASSWORD)
    await cognitoClient.send(new AdminSetUserPasswordCommand({
      UserPoolId: userPoolId,
      Username: email,
      Password: password,
      Permanent: true,
    }));

    // 3. Create canonical public."User" row (auth-service owns all User writes)
    let userId: string;
    try {
      const userRows = await query<{ id: string }>(
        `INSERT INTO "User" ("id", "organizationId", "email", "name", "cognitoSub", "role", "status", "createdAt", "updatedAt")
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'ACTIVE', NOW(), NOW())
         RETURNING "id"`,
        [organizationId, email, fullName, cognitoSub, appRole],
      );
      userId = userRows[0].id;
    } catch (dbErr: any) {
      // Cognito user created but DB write failed — compensate by deleting Cognito user
      logger.error(
        { err: dbErr, email, cognitoSub, phase: 'create-tenant.db-insert' },
        'User row INSERT failed after Cognito creation — deleting Cognito user to compensate',
      );
      try {
        await cognitoClient.send(new AdminDeleteUserCommand({
          UserPoolId: userPoolId,
          Username: email,
        }));
        logger.info({ email }, 'Compensating Cognito delete succeeded');
      } catch (cleanupErr) {
        logger.error(
          { err: cleanupErr, email, cognitoSub },
          'CRITICAL: Cognito compensating delete FAILED — orphaned Cognito user remains',
        );
      }
      throw dbErr;
    }

    // 4. Add user_organizations membership row for the new org
    await query(
      `INSERT INTO public.user_organizations (user_id, organization_id, role, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, organization_id) DO NOTHING`,
      [userId, organizationId, appRole],
    );

    // 5. Persist legal acceptance rows (one per document) — must succeed or fail the identity creation
    if (legalAcceptance && legalAcceptance.length > 0) {
      try {
        await persistLegalAcceptance(
          userId,
          legalAcceptance,
          'tenant-invite',
          getClientIp(req),
          req.headers['user-agent'] as string | undefined,
        );
      } catch (legalErr: any) {
        // Legal acceptance persistence failed — compensate by deleting identity
        logger.error(
          { err: legalErr, email, cognitoSub, userId, phase: 'create-tenant.legal-acceptance' },
          'LegalAcceptance INSERT failed — compensating by deleting Cognito user + User row',
        );
        try {
          await query(`DELETE FROM "User" WHERE "id" = $1`, [userId]);
          await cognitoClient.send(new AdminDeleteUserCommand({
            UserPoolId: userPoolId,
            Username: email,
          }));
          logger.info({ email, userId }, 'Compensating cleanup succeeded after legal acceptance failure');
        } catch (cleanupErr) {
          logger.error(
            { err: cleanupErr, email, cognitoSub, userId },
            'CRITICAL: Compensating cleanup FAILED after legal acceptance failure',
          );
        }
        throw legalErr;
      }
    }

    logger.info(
      { email, cognitoSub, userId, legalDocsAccepted: legalAcceptance?.length ?? 0 },
      'Tenant identity created: Cognito + User row + user_organizations + LegalAcceptance',
    );

    res.status(201).json({ cognitoSub, userId, existingUser: false });
  } catch (err: any) {
    if (err.name === 'UsernameExistsException') {
      return next(new ValidationError('An account with this email already exists'));
    }
    if (err.name === 'InvalidPasswordException') {
      return next(new ValidationError('Password does not meet requirements'));
    }
    next(err);
  }
});
// --- POST /delete-tenant (internal, service-to-service) ---
// Compensating cleanup: deletes Cognito user + User row.
// Used by tenant-service when downstream provisioning fails after identity creation.
const deleteTenantSchema = z.object({
  cognitoSub: z.string().min(1),
  email: z.string().email(),
});

/**
 * POST /delete-tenant — Internal service-to-service endpoint.
 *
 * Compensating action for failed invitation acceptance:
 * deletes the Cognito identity and the canonical public."User" row.
 */
router.post('/delete-tenant', validateBody(deleteTenantSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const serviceKey = req.headers['x-internal-service-key'] as string | undefined;
    if (!INTERNAL_SERVICE_KEY || !serviceKey || serviceKey !== INTERNAL_SERVICE_KEY) {
      throw new UnauthorizedError('Invalid or missing internal service key');
    }

    if (!userPoolId) {
      throw new ValidationError('Cognito user pool ID is not configured');
    }

    const { cognitoSub, email } = req.body as z.infer<typeof deleteTenantSchema>;

    // 1. Delete Cognito user
    try {
      await cognitoClient.send(new AdminDeleteUserCommand({
        UserPoolId: userPoolId,
        Username: email,
      }));
      logger.info({ email, cognitoSub }, 'Cognito user deleted (compensating cleanup)');
    } catch (cogErr: any) {
      if (cogErr.name !== 'UserNotFoundException') {
        logger.error({ err: cogErr, email }, 'Failed to delete Cognito user during cleanup');
        throw cogErr;
      }
      logger.warn({ email }, 'Cognito user not found during cleanup — already deleted');
    }

    // 2. Delete User row
    const deleteResult = await query(
      `DELETE FROM "User" WHERE "cognitoSub" = $1 RETURNING "id"`,
      [cognitoSub],
    );

    const deletedCount = Array.isArray(deleteResult) ? deleteResult.length : 0;
    logger.info({ cognitoSub, deletedRows: deletedCount }, 'User row deleted (compensating cleanup)');

    res.json({ deleted: true, cognitoSub, userRowsDeleted: deletedCount });
  } catch (err) {
    next(err);
  }
});

export { router as authRouter };
