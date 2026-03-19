# Dev User Management

## Problem

LeaseBase stores user identity in **two separate systems**:

1. **AWS Cognito** — authentication provider (email/password, tokens)
2. **Application DB** (`"User"` table) — app-level profile, role, org membership

If you clear the DB but forget Cognito (or vice versa), signup will fail with:

> "An account with this email already exists"

This happens because the `/register` endpoint calls Cognito's `SignUp` first. If the email already exists in the Cognito pool, Cognito rejects the request before any DB check occurs.

## Quick Fix — Remove a Stuck Dev User

### Option A: CLI script (recommended)

```bash
# Set the dev Cognito pool
export COGNITO_USER_POOL_ID=us-west-2_zG8uuktxr

# Optionally set DB connection for full cleanup
# export DATABASE_URL=postgresql://user:pass@host:5432/leasebase?schema=auth

# Inspect first
npm run dev:inspect-user -- user@example.com

# Delete from both Cognito and DB
npm run dev:delete-user -- user@example.com

# List all users in the pool
npm run dev:list-users
```

### Option B: AWS CLI (Cognito only)

```bash
# Delete from Cognito
aws cognito-idp admin-delete-user \
  --region us-west-2 \
  --user-pool-id us-west-2_zG8uuktxr \
  --username "user@example.com"

# Verify deletion
aws cognito-idp admin-get-user \
  --region us-west-2 \
  --user-pool-id us-west-2_zG8uuktxr \
  --username "user@example.com"
# Expected: UserNotFoundException
```

Then clean DB if needed:

```sql
-- Connect to the auth-service DB schema
DELETE FROM "User" WHERE LOWER("email") = 'user@example.com';
```

## Full Dev Data Reset

When resetting all dev data, you must clean **both** stores:

```bash
# 1. Clear Cognito (list + delete all)
export COGNITO_USER_POOL_ID=us-west-2_zG8uuktxr

npm run dev:list-users
# Then for each user:
npm run dev:delete-user -- <email>

# 2. Clear DB (truncate tables, Prisma reset, etc.)
# ... your existing DB reset process ...
```

## Architecture Notes

- The signup flow is: **Cognito SignUp → DB bootstrap (Org + User + Subscription)**
- If Cognito succeeds but DB bootstrap fails, the user can still verify email and log in. The `/me` endpoint will detect the missing DB record and fail closed.
- Email is normalized to lowercase in all paths (`normalizeEmail()`).
- The `dev:inspect-user` script checks both stores and reports which one(s) contain the user.

## Dev Environment Reference

| Resource | Value |
|----------|-------|
| Cognito User Pool | `us-west-2_zG8uuktxr` (`leasebase-dev-v2-users`) |
| Cognito Web Client | `qvl3hdci4qkra8ggegdsg3uis` |
| Region | `us-west-2` |
| ECS Cluster | `leasebase-dev-v2-cluster` |
| ECS Service | `leasebase-dev-v2-auth-service` |
