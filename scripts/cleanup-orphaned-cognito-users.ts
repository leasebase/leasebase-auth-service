/**
 * cleanup-orphaned-cognito-users.ts
 *
 * Identifies and removes orphaned Cognito users created by failed registration
 * bootstrap attempts. An "orphan" is a Cognito user with NO corresponding
 * public."User" row in the database.
 *
 * Safety:
 * - Only deletes users that are UNCONFIRMED in Cognito AND missing from DB.
 * - Performs a dry-run by default; pass --apply to actually delete.
 * - Logs every action for audit trail.
 *
 * Prerequisites:
 *   - DATABASE_URL env var pointing to the target database
 *   - COGNITO_USER_POOL_ID env var
 *   - COGNITO_REGION env var (defaults to us-west-2)
 *   - AWS credentials with cognito-idp:ListUsers and cognito-idp:AdminDeleteUser
 *
 * Usage:
 *   npx tsx scripts/cleanup-orphaned-cognito-users.ts          # dry-run
 *   npx tsx scripts/cleanup-orphaned-cognito-users.ts --apply  # actually delete
 */

import {
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminDeleteUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { Pool } from 'pg';

const region = process.env.COGNITO_REGION || 'us-west-2';
const userPoolId = process.env.COGNITO_USER_POOL_ID;
const databaseUrl = process.env.DATABASE_URL;
const dryRun = !process.argv.includes('--apply');

if (!userPoolId) {
  console.error('ERROR: COGNITO_USER_POOL_ID is required');
  process.exit(1);
}
if (!databaseUrl) {
  console.error('ERROR: DATABASE_URL is required');
  process.exit(1);
}

const cognito = new CognitoIdentityProviderClient({ region });
const pool = new Pool({ connectionString: databaseUrl });

interface CognitoUser {
  username: string;
  sub: string;
  email: string;
  status: string;
}

async function listUnconfirmedCognitoUsers(): Promise<CognitoUser[]> {
  const users: CognitoUser[] = [];
  let paginationToken: string | undefined;

  do {
    const command = new ListUsersCommand({
      UserPoolId: userPoolId,
      Filter: 'cognito:user_status = "UNCONFIRMED"',
      Limit: 60,
      PaginationToken: paginationToken,
    });

    const response = await cognito.send(command);
    for (const user of response.Users ?? []) {
      const attrs = user.Attributes ?? [];
      const sub = attrs.find(a => a.Name === 'sub')?.Value ?? '';
      const email = attrs.find(a => a.Name === 'email')?.Value ?? '';
      users.push({
        username: user.Username ?? '',
        sub,
        email,
        status: user.UserStatus ?? '',
      });
    }
    paginationToken = response.PaginationToken;
  } while (paginationToken);

  return users;
}

async function findOrphans(cognitoUsers: CognitoUser[]): Promise<CognitoUser[]> {
  if (cognitoUsers.length === 0) return [];

  const subs = cognitoUsers.map(u => u.sub).filter(Boolean);
  if (subs.length === 0) return cognitoUsers;

  // Query DB for which subs actually exist
  const placeholders = subs.map((_, i) => `$${i + 1}`).join(', ');
  const result = await pool.query(
    `SELECT "cognitoSub" FROM "User" WHERE "cognitoSub" IN (${placeholders})`,
    subs,
  );
  const existingSubs = new Set(result.rows.map((r: any) => r.cognitoSub));

  return cognitoUsers.filter(u => !existingSubs.has(u.sub));
}

async function main() {
  console.log(`\n=== Orphaned Cognito User Cleanup ===`);
  console.log(`Mode: ${dryRun ? 'DRY RUN (pass --apply to delete)' : 'APPLY (will delete orphans)'}`);
  console.log(`User Pool: ${userPoolId}`);
  console.log(`Region: ${region}\n`);

  // 1. List unconfirmed Cognito users
  console.log('Listing UNCONFIRMED Cognito users...');
  const unconfirmed = await listUnconfirmedCognitoUsers();
  console.log(`Found ${unconfirmed.length} unconfirmed user(s) in Cognito.\n`);

  if (unconfirmed.length === 0) {
    console.log('No orphans to clean up.');
    await pool.end();
    return;
  }

  // 2. Identify orphans (no DB User row)
  console.log('Checking which have no corresponding DB User row...');
  const orphans = await findOrphans(unconfirmed);
  console.log(`Found ${orphans.length} orphaned user(s).\n`);

  if (orphans.length === 0) {
    console.log('All unconfirmed users have DB records. Nothing to clean up.');
    await pool.end();
    return;
  }

  // 3. Report orphans
  console.log('Orphaned users:');
  for (const orphan of orphans) {
    console.log(`  - ${orphan.email} (sub: ${orphan.sub}, status: ${orphan.status})`);
  }
  console.log();

  // 4. Delete orphans (or report dry-run)
  let deleted = 0;
  let failed = 0;
  for (const orphan of orphans) {
    if (dryRun) {
      console.log(`[DRY RUN] Would delete: ${orphan.email} (sub: ${orphan.sub})`);
      deleted++;
    } else {
      try {
        await cognito.send(new AdminDeleteUserCommand({
          UserPoolId: userPoolId,
          Username: orphan.username,
        }));
        console.log(`[DELETED] ${orphan.email} (sub: ${orphan.sub})`);
        deleted++;
      } catch (err: any) {
        console.error(`[FAILED] ${orphan.email}: ${err.message}`);
        failed++;
      }
    }
  }

  console.log(`\n=== Summary ===`);
  console.log(`Total orphans found: ${orphans.length}`);
  console.log(`${dryRun ? 'Would delete' : 'Deleted'}: ${deleted}`);
  if (failed > 0) console.log(`Failed: ${failed}`);

  await pool.end();
}

main().catch((err) => {
  console.error('Fatal error:', err);
  pool.end();
  process.exit(1);
});
