import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
  ResendConfirmationCodeCommand,
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
} from '@leasebase/service-common';

const router = Router();

const region = process.env.COGNITO_REGION || 'us-west-2';
// Accept both COGNITO_CLIENT_ID (canonical) and COGNITO_WEB_CLIENT_ID (legacy IaC name)
const clientId = process.env.COGNITO_CLIENT_ID || process.env.COGNITO_WEB_CLIENT_ID || '';
const cognitoClient = new CognitoIdentityProviderClient({ region });

// --- Schemas ---
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
});

const confirmEmailSchema = z.object({
  email: z.string().email(),
  code: z.string().min(1),
});

const resendSchema = z.object({
  email: z.string().email(),
});

// --- POST /login ---
router.post('/login', validateBody(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!clientId) {
      throw new ValidationError('Cognito client ID is not configured');
    }

    const { email, password } = req.body;

    const command = new InitiateAuthCommand({
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      ClientId: clientId,
      AuthParameters: {
        USERNAME: email,
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
      return next(new ValidationError('Please verify your email before logging in'));
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

    const { email, password, firstName, lastName } = req.body;

    const command = new SignUpCommand({
      ClientId: clientId,
      Username: email,
      Password: password,
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'given_name', Value: firstName },
        { Name: 'family_name', Value: lastName },
      ],
    });

    const response = await cognitoClient.send(command);

    res.status(201).json({
      userConfirmed: response.UserConfirmed ?? false,
      userSub: response.UserSub ?? '',
      message: response.UserConfirmed
        ? 'Registration successful. You can now log in.'
        : 'Registration successful. Please check your email for a verification code.',
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

    await cognitoClient.send(new ConfirmSignUpCommand({
      ClientId: clientId,
      Username: email,
      ConfirmationCode: code,
    }));

    res.json({ message: 'Email verified successfully. You can now sign in.' });
  } catch (err: any) {
    if (err.name === 'CodeMismatchException') {
      return next(new ValidationError('The verification code is incorrect'));
    }
    if (err.name === 'ExpiredCodeException') {
      return next(new ValidationError('The verification code has expired'));
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

    await cognitoClient.send(new ResendConfirmationCodeCommand({
      ClientId: clientId,
      Username: req.body.email,
    }));

    res.json({ message: 'A new verification code has been sent to your email.' });
  } catch (err: any) {
    if (err.name === 'UserNotFoundException') {
      return next(new ValidationError('No account found for this email'));
    }
    next(err);
  }
});

// --- GET /me ---
router.get('/me', requireAuth, (req: Request, res: Response) => {
  const user = (req as AuthenticatedRequest).user;
  res.json({
    id: user.userId,
    orgId: user.orgId,
    email: user.email,
    name: user.name,
    role: user.role,
  });
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

export { router as authRouter };
