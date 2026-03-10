#!/usr/bin/env tsx
/**
 * Dev-only user management tool for LeaseBase.
 *
 * Inspects and optionally deletes a user from Cognito and the application DB.
 * Targets only the configured dev environment (reads env vars or deploy config).
 *
 * Usage:
 *   npx tsx scripts/dev-user.ts inspect <email>
 *   npx tsx scripts/dev-user.ts delete  <email>
 *   npx tsx scripts/dev-user.ts list
 *
 * Or via npm scripts:
 *   npm run dev:inspect-user -- <email>
 *   npm run dev:delete-user  -- <email>
 *   npm run dev:list-users
 */

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminDeleteUserCommand,
  ListUsersCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { Pool } from 'pg';

// ── Config ─────────────────────────────────────────────────────────────────

const REGION = process.env.COGNITO_REGION || process.env.AWS_REGION || 'us-west-2';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';
const DB_URL = process.env.DATABASE_URL || '';

if (!USER_POOL_ID) {
  console.error('ERROR: COGNITO_USER_POOL_ID is required.');
  console.error('  Set it via env var, or export from your .env / deploy config.');
  process.exit(1);
}

const cognito = new CognitoIdentityProviderClient({ region: REGION });

function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

// ── Cognito helpers ────────────────────────────────────────────────────────

async function cognitoGetUser(email: string): Promise<{
  exists: boolean;
  username?: string;
  status?: string;
  sub?: string;
  attributes?: Record<string, string>;
}> {
  try {
    const res = await cognito.send(
      new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: email }),
    );
    const attrs: Record<string, string> = {};
    for (const a of res.UserAttributes ?? []) {
      if (a.Name && a.Value) attrs[a.Name] = a.Value;
    }
    return {
      exists: true,
      username: res.Username,
      status: res.UserStatus,
      sub: attrs['sub'],
      attributes: attrs,
    };
  } catch (err: any) {
    if (err.name === 'UserNotFoundException') {
      return { exists: false };
    }
    throw err;
  }
}

async function cognitoDeleteUser(email: string): Promise<boolean> {
  try {
    await cognito.send(
      new AdminDeleteUserCommand({ UserPoolId: USER_POOL_ID, Username: email }),
    );
    return true;
  } catch (err: any) {
    if (err.name === 'UserNotFoundException') return false;
    throw err;
  }
}

async function cognitoListUsers(): Promise<
  Array<{ email: string; username: string; status: string; created: string }>
> {
  const res = await cognito.send(
    new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60 }),
  );
  return (res.Users ?? []).map((u) => ({
    email:
      u.Attributes?.find((a) => a.Name === 'email')?.Value ?? u.Username ?? '',
    username: u.Username ?? '',
    status: u.UserStatus ?? '',
    created: u.UserCreateDate?.toISOString() ?? '',
  }));
}

// ── DB helpers ─────────────────────────────────────────────────────────────

async function dbLookupUser(
  email: string,
): Promise<{ exists: boolean; rows: Array<Record<string, unknown>> }> {
  if (!DB_URL) {
    return { exists: false, rows: [] };
  }
  const pool = new Pool({ connectionString: DB_URL, max: 1 });
  try {
    // Search across the auth schema's User table
    const result = await pool.query(
      `SELECT "id", "email", "name", "role", "cognitoSub", "organizationId", "status"
       FROM "User"
       WHERE LOWER("email") = $1`,
      [email],
    );
    return { exists: result.rowCount! > 0, rows: result.rows };
  } catch (err: any) {
    // Table might not exist in this schema
    if (err.code === '42P01') {
      console.warn('  ⚠ "User" table not found — DB might use a different schema');
      return { exists: false, rows: [] };
    }
    throw err;
  } finally {
    await pool.end();
  }
}

async function dbDeleteUser(email: string): Promise<number> {
  if (!DB_URL) return 0;
  const pool = new Pool({ connectionString: DB_URL, max: 1 });
  try {
    // Delete user and cascade org/subscription if this was the only user
    const userResult = await pool.query(
      `DELETE FROM "User" WHERE LOWER("email") = $1 RETURNING "id", "organizationId"`,
      [email],
    );
    const deleted = userResult.rowCount ?? 0;

    // Clean up empty orgs
    for (const row of userResult.rows) {
      const orgId = row.organizationId;
      if (orgId) {
        const remaining = await pool.query(
          `SELECT COUNT(*) as cnt FROM "User" WHERE "organizationId" = $1`,
          [orgId],
        );
        if (Number(remaining.rows[0]?.cnt) === 0) {
          await pool.query(`DELETE FROM "Subscription" WHERE "organizationId" = $1`, [orgId]);
          await pool.query(`DELETE FROM "Organization" WHERE "id" = $1`, [orgId]);
          console.log(`  🗑  Deleted empty Organization ${orgId} and its Subscription`);
        }
      }
    }
    return deleted;
  } catch (err: any) {
    if (err.code === '42P01') {
      console.warn('  ⚠ "User" table not found');
      return 0;
    }
    throw err;
  } finally {
    await pool.end();
  }
}

// ── Commands ───────────────────────────────────────────────────────────────

/**
 * Repair a "stuck" user: exists in Cognito but has no DB records.
 * Creates Organization + User + Subscription using Cognito attributes.
 */
async function repair(email: string): Promise<void> {
  const normalized = normalizeEmail(email);
  console.log(`\nRepairing stuck user: ${normalized}`);
  console.log(`  Pool:   ${USER_POOL_ID}`);
  console.log(`  Region: ${REGION}`);
  console.log(`  DB:     ${DB_URL ? 'configured' : 'NOT configured (cannot repair)'}\n`);

  if (!DB_URL) {
    console.error('ERROR: DATABASE_URL is required for repair.');
    process.exit(1);
  }

  // 1. Check Cognito
  const cog = await cognitoGetUser(normalized);
  if (!cog.exists || !cog.sub) {
    console.error('  ❌ User not found in Cognito — nothing to repair.');
    process.exit(1);
  }
  console.log(`  ✅ COGNITO: found (sub=${cog.sub}, status=${cog.status})`);

  // 2. Check DB — must NOT already exist
  const db = await dbLookupUser(normalized);
  if (db.exists) {
    console.log('  ✅ DATABASE: user already exists — no repair needed.');
    for (const row of db.rows) {
      console.log(`     id=${row.id} role=${row.role} status=${row.status}`);
    }
    return;
  }
  console.log('  ❌ DATABASE: user NOT found — will create bootstrap records.\n');

  // 3. Determine role from Cognito custom:role or default to OWNER
  const cognitoRole = cog.attributes?.['custom:role'] || '';
  const roleMap: Record<string, { role: string; orgType: string }> = {
    OWNER: { role: 'OWNER', orgType: 'LANDLORD' },
    ORG_ADMIN: { role: 'ORG_ADMIN', orgType: 'PM_COMPANY' },
    PROPERTY_MANAGER: { role: 'ORG_ADMIN', orgType: 'PM_COMPANY' },
  };
  const mapping = roleMap[cognitoRole.toUpperCase()] || roleMap['OWNER'];
  const fullName = `${cog.attributes?.['given_name'] ?? ''} ${cog.attributes?.['family_name'] ?? ''}`.trim() || normalized;

  console.log(`  Role:     ${mapping.role} (from Cognito custom:role="${cognitoRole}")`);
  console.log(`  Org Type: ${mapping.orgType}`);
  console.log(`  Name:     ${fullName}\n`);

  // 4. Create records in a transaction
  const pool = new Pool({ connectionString: DB_URL, max: 1 });
  try {
    await pool.query('BEGIN');

    const orgResult = await pool.query(
      `INSERT INTO "Organization" ("id", "type", "name", "plan", "createdAt", "updatedAt")
       VALUES (gen_random_uuid(), $1::"OrganizationType", $2, 'basic', NOW(), NOW())
       RETURNING "id"`,
      [mapping.orgType, `${fullName}'s Organization`],
    );
    const orgId = orgResult.rows[0].id;

    await pool.query(
      `INSERT INTO "User" ("id", "organizationId", "email", "name", "cognitoSub", "role", "status", "createdAt", "updatedAt")
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5::"UserRole", 'ACTIVE', NOW(), NOW())`,
      [orgId, normalized, fullName, cog.sub, mapping.role],
    );

    await pool.query(
      `INSERT INTO "Subscription" ("id", "organizationId", "plan", "unitCount", "status", "createdAt", "updatedAt")
       VALUES (gen_random_uuid(), $1, 'basic', 0, 'ACTIVE'::"SubscriptionStatus", NOW(), NOW())`,
      [orgId],
    );

    await pool.query('COMMIT');
    console.log(`  ✅ Created Organization (${orgId}), User, and Subscription.`);
    console.log(`  User can now log in successfully.\n`);
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('  ❌ Failed to create DB records:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

async function inspect(email: string): Promise<void> {
  const normalized = normalizeEmail(email);
  console.log(`\nInspecting user: ${normalized}`);
  console.log(`  Pool:   ${USER_POOL_ID}`);
  console.log(`  Region: ${REGION}`);
  console.log(`  DB:     ${DB_URL ? 'configured' : 'not configured (skipping DB check)'}\n`);

  // Cognito
  const cog = await cognitoGetUser(normalized);
  if (cog.exists) {
    console.log('  ✅ COGNITO: user exists');
    console.log(`     Username: ${cog.username}`);
    console.log(`     Sub:      ${cog.sub}`);
    console.log(`     Status:   ${cog.status}`);
    if (cog.attributes) {
      console.log(`     Role:     ${cog.attributes['custom:role'] ?? '(none)'}`);
      console.log(`     Name:     ${cog.attributes['given_name'] ?? ''} ${cog.attributes['family_name'] ?? ''}`);
    }
  } else {
    console.log('  ❌ COGNITO: user NOT found');
  }

  // DB
  const db = await dbLookupUser(normalized);
  if (db.exists) {
    console.log(`\n  ✅ DATABASE: ${db.rows.length} row(s) found`);
    for (const row of db.rows) {
      console.log(`     id=${row.id} role=${row.role} status=${row.status} cognitoSub=${row.cognitoSub}`);
    }
  } else {
    console.log('\n  ❌ DATABASE: user NOT found');
  }

  // Summary
  console.log('\n  ── Summary ──');
  if (cog.exists && db.exists) {
    console.log('  User exists in: BOTH Cognito and DB');
  } else if (cog.exists) {
    console.log('  User exists in: Cognito ONLY (DB was cleaned but Cognito was not)');
  } else if (db.exists) {
    console.log('  User exists in: DB ONLY (orphaned DB record, missing Cognito identity)');
  } else {
    console.log('  User exists in: NEITHER');
  }
  console.log();
}

async function deleteUser(email: string): Promise<void> {
  const normalized = normalizeEmail(email);
  console.log(`\nDeleting user: ${normalized}`);
  console.log(`  Pool:   ${USER_POOL_ID}`);
  console.log(`  Region: ${REGION}\n`);

  // Cognito
  const cogDeleted = await cognitoDeleteUser(normalized);
  console.log(cogDeleted ? '  🗑  Cognito: user deleted' : '  ⏭  Cognito: user not found (nothing to delete)');

  // DB
  const dbDeleted = await dbDeleteUser(normalized);
  console.log(dbDeleted > 0 ? `  🗑  Database: ${dbDeleted} row(s) deleted` : '  ⏭  Database: user not found (nothing to delete)');

  console.log('\n  ✅ Cleanup complete. User can now re-register.\n');
}

async function listUsers(): Promise<void> {
  console.log(`\nCognito users in pool ${USER_POOL_ID} (${REGION}):\n`);
  const users = await cognitoListUsers();
  if (users.length === 0) {
    console.log('  (no users found)');
  } else {
    for (const u of users) {
      console.log(`  ${u.email.padEnd(35)} ${u.status.padEnd(15)} ${u.created}`);
    }
    console.log(`\n  Total: ${users.length} user(s)\n`);
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const [command, email] = process.argv.slice(2);

  switch (command) {
    case 'inspect':
      if (!email) {
        console.error('Usage: dev-user.ts inspect <email>');
        process.exit(1);
      }
      await inspect(email);
      break;

    case 'delete':
      if (!email) {
        console.error('Usage: dev-user.ts delete <email>');
        process.exit(1);
      }
      await deleteUser(email);
      break;

    case 'list':
      await listUsers();
      break;

    case 'repair':
      if (!email) {
        console.error('Usage: dev-user.ts repair <email>');
        process.exit(1);
      }
      await repair(email);
      break;

    default:
      console.error('Usage: dev-user.ts <inspect|delete|repair|list> [email]');
      console.error('\nCommands:');
      console.error('  inspect <email>  — check if user exists in Cognito and/or DB');
      console.error('  delete  <email>  — remove user from Cognito and DB');
      console.error('  repair  <email>  — create missing DB records for a Cognito-only user');
      console.error('  list             — list all Cognito users in the pool');
      process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
