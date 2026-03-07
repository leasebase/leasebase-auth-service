# LeaseBase auth-service

Authentication and authorization service. Extends Cognito with app-specific auth logic.

## Stack

- **Runtime**: Node.js / NestJS (planned)
- **Container**: Docker -> ECS Fargate
- **Registry**: ECR `leasebase-{env}-v2-auth-service`
- **Port**: 3000

## Infrastructure

Managed by Terraform in [leasebase-iac](https://github.com/motart/leasebase-iac).

## Auth Flow

1. Frontend sends `POST /api/auth/login` with email + password.
2. BFF gateway proxies to `POST /internal/auth/login`, which authenticates via Cognito `USER_PASSWORD_AUTH`.
3. On success, returns `{ accessToken, idToken, refreshToken, expiresIn }`.
4. Frontend stores the **access token** and sends it as `Authorization: Bearer <accessToken>` on subsequent requests.
5. Protected routes (e.g. `GET /internal/auth/me`) use `requireAuth` middleware from `@leasebase/service-common`, which verifies the access token (signature, issuer, expiry, `token_use=access`, `client_id`).

### Token Verification (Cognito-specific)

Cognito access tokens do **not** contain an `aud` claim — they use `client_id` instead. The shared JWT verifier in `@leasebase/service-common` handles this:
- Access tokens → validates `client_id` matches `COGNITO_CLIENT_ID`
- ID tokens → validates `aud` matches `COGNITO_CLIENT_ID`

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `COGNITO_REGION` | Yes | AWS region (e.g. `us-west-2`) |
| `COGNITO_USER_POOL_ID` | Yes | Cognito user pool ID |
| `COGNITO_CLIENT_ID` | Yes | Cognito app client ID (canonical name) |

## Getting Started

```bash
npm install
npm run dev
npm test
```

---

## Docker Tagging Strategy

Every CI build on `develop` pushes **two Docker image tags** to Amazon ECR:

- **`dev-latest`** — moving tag that always points to the most recent develop build. ECS services are configured to deploy this tag.
- **`<git-sha>`** — immutable tag using the full 40-character commit SHA, retained for traceability and rollback.

**ECS deployments** reference `dev-latest`. After pushing, the pipeline registers a new ECS task definition with `dev-latest` and forces a new deployment.

**Rollbacks**: to roll back to a previous build, update the ECS task definition to reference the specific `<git-sha>` tag of the desired commit.
