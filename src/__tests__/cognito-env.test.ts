import { describe, it, expect, afterEach } from 'vitest';

describe('Cognito client ID env resolution', () => {
  const ORIGINAL_ENV = { ...process.env };

  afterEach(() => {
    // Restore original env after each test
    process.env = { ...ORIGINAL_ENV };
  });

  it('prefers COGNITO_CLIENT_ID when both are set', () => {
    process.env.COGNITO_CLIENT_ID = 'canonical-id';
    process.env.COGNITO_WEB_CLIENT_ID = 'legacy-id';

    const clientId = process.env.COGNITO_CLIENT_ID || process.env.COGNITO_WEB_CLIENT_ID || '';
    expect(clientId).toBe('canonical-id');
  });

  it('falls back to COGNITO_WEB_CLIENT_ID when COGNITO_CLIENT_ID is not set', () => {
    delete process.env.COGNITO_CLIENT_ID;
    process.env.COGNITO_WEB_CLIENT_ID = 'legacy-id';

    const clientId = process.env.COGNITO_CLIENT_ID || process.env.COGNITO_WEB_CLIENT_ID || '';
    expect(clientId).toBe('legacy-id');
  });

  it('returns empty string when neither is set', () => {
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.COGNITO_WEB_CLIENT_ID;

    const clientId = process.env.COGNITO_CLIENT_ID || process.env.COGNITO_WEB_CLIENT_ID || '';
    expect(clientId).toBe('');
  });
});
