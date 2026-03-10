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

// --- Schemas ---
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

/** Allowed signup user types sent by the web registration form. */
const SIGNUP_USER_TYPES = ['OWNER', 'PROPERTY_MANAGER'] as const;
type SignupUserType = (typeof SIGNUP_USER_TYPES)[number];

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  userType: z.enum(SIGNUP_USER_TYPES),
});

/**
 * Map the UI signup userType to the internal application role.
 *
 *   OWNER            → OWNER       (individual landlord)
 *   PROPERTY_MANAGER → ORG_ADMIN   (admin of a PM company)
 */
function mapUserTypeToRole(userType: SignupUserType): string {
  switch (userType) {
    case 'OWNER':            return 'OWNER';
    case 'PROPERTY_MANAGER': return 'ORG_ADMIN';
  }
}

/**
 * Map signup userType to the Organization type used in the DB.
 *
 *   OWNER            → LANDLORD
 *   PROPERTY_MANAGER → PM_COMPANY
 */
function mapUserTypeToOrgType(userType: SignupUserType): string {
  return userType === 'PROPERTY_MANAGER' ? 'PM_COMPANY' : 'LANDLORD';
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

    if (!response.AuthenticationResult) {
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
    next(err);
  }
});

// --- POST /register ---
router.post('/register', validateBody(registerSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, password, firstName, lastName, userType } = req.body as z.infer<typeof registerSchema>;
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
        const orgId = orgRows[0]?.id;

        if (orgId) {
          // Create user with correct role and cognitoSub
          await query(
            `INSERT INTO "User" ("id", "organizationId", "email", "name", "cognitoSub", "role", "status", "createdAt", "updatedAt")
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'ACTIVE', NOW(), NOW())`,
            [orgId, normalized, fullName, cognitoSub, appRole],
          );

          // Create subscription (basic plan)
          await query(
            `INSERT INTO "Subscription" ("id", "organizationId", "plan", "unitCount", "status", "createdAt", "updatedAt")
             VALUES (gen_random_uuid(), $1, 'basic', 0, 'ACTIVE', NOW(), NOW())`,
            [orgId],
          );

          logger.info(
            { email, userType, appRole, orgId, cognitoSub },
            'Registration bootstrap: created Organization + User + Subscription',
          );
        }
      } catch (bootstrapErr) {
        // Cognito user is created — log the bootstrap failure but do not
        // fail the registration.  The /me first-login upsert in the
        // monolith can recover, and the user can still verify email.
        logger.error(
          { err: bootstrapErr, email, userType },
          'Registration bootstrap failed — Cognito user created but DB records may be missing',
        );
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
      return next(new ValidationError('An account with this email already exists'));
    }
    if (err.name === 'InvalidPasswordException') {
      return next(new ValidationError('Password does not meet requirements'));
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
// The requireAuth middleware may set role to a default (TENANT) when the JWT
// custom:role claim is absent. For /me we need the DB-backed role so that
// existing OWNER users are not incorrectly downgraded to TENANT.
router.get('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    // In dev-bypass mode the role is set correctly from the header — skip DB.
    if (user.sub !== 'dev-bypass') {
      // Look up the user's authoritative role from the DB.
      const dbUser = await queryOne<{ id: string; email: string; name: string; role: string }>(
        `SELECT "id", "email", "name", "role" FROM "User" WHERE "cognitoSub" = $1`,
        [user.sub],
      );

      if (dbUser) {
        res.json({
          id: dbUser.id,
          orgId: user.orgId,
          email: dbUser.email,
          name: dbUser.name,
          role: dbUser.role,
        });
        return;
      }

      // No DB user and no trustworthy role source — fail closed.
      // The JWT-derived role may be TENANT fallback from requireAuth, which
      // we no longer trust.  Return 401 so the client clears the session.
      logger.warn(
        { sub: user.sub, email: user.email },
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
// Creates a Cognito user for an invited tenant with a pre-set permanent password.
// Protected by X-Internal-Service-Key header.
const createTenantSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
});

/**
 * POST /create-tenant — Internal service-to-service endpoint.
 *
 * Creates a Cognito identity for a tenant and returns the cognitoSub.
 * Does NOT create application DB records — the calling service (tenant-service)
 * is responsible for all application DB writes.
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

    const { email, password, firstName, lastName } = req.body as z.infer<typeof createTenantSchema>;
    const appRole = 'TENANT';

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

    logger.info({ email, cognitoSub }, 'Tenant Cognito identity created via invitation');

    res.status(201).json({ cognitoSub });
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

export { router as authRouter };
