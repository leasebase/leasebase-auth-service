import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import {
  requireAuth,
  validateBody,
  queryOne,
  logger,
  type AuthenticatedRequest,
} from '@leasebase/service-common';

const router = Router();

// ── Schemas ──────────────────────────────────────────────────────────────────

const updateProfileSchema = z.object({
  first_name: z.string().max(100).optional(),
  last_name: z.string().max(100).optional(),
  phone_number: z.string().max(30).optional(),
  avatar_url: z.string().url().max(2048).nullable().optional(),
  timezone: z.string().max(50).optional(),
  language: z.string().max(10).optional(),
});

const updateOwnerProfileSchema = z.object({
  company_name: z.string().max(200).nullable().optional(),
  business_type: z.string().max(100).nullable().optional(),
  primary_color: z.string().max(20).nullable().optional(),
  secondary_color: z.string().max(20).nullable().optional(),
  theme_mode: z.enum(['light', 'dark', 'system']).optional(),
  logo_url: z.string().url().max(2048).nullable().optional(),
  billing_email: z.string().email().nullable().optional(),
  billing_address: z.string().max(500).nullable().optional(),
  tax_id: z.string().max(50).nullable().optional(),
});

// ══════════════════════════════════════════════════════════════════════════════
// BASE USER PROFILE — all personas
// ══════════════════════════════════════════════════════════════════════════════

// GET / — Fetch the authenticated user's base profile
router.get('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const row = await queryOne(
      `SELECT user_id, first_name, last_name, phone_number, avatar_url,
              timezone, language, created_at, updated_at
       FROM user_profiles
       WHERE user_id = $1`,
      [user.userId],
    );

    res.json({ data: row || null });
  } catch (err) { next(err); }
});

// PUT / — Upsert the authenticated user's base profile
router.put('/', requireAuth, validateBody(updateProfileSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateProfileSchema>;

      const row = await queryOne(
        `INSERT INTO user_profiles (user_id, first_name, last_name, phone_number, avatar_url, timezone, language, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           first_name = COALESCE($2, user_profiles.first_name),
           last_name = COALESCE($3, user_profiles.last_name),
           phone_number = COALESCE($4, user_profiles.phone_number),
           avatar_url = COALESCE($5, user_profiles.avatar_url),
           timezone = COALESCE($6, user_profiles.timezone),
           language = COALESCE($7, user_profiles.language),
           updated_at = NOW()
         RETURNING *`,
        [
          user.userId,
          body.first_name ?? null,
          body.last_name ?? null,
          body.phone_number ?? null,
          body.avatar_url ?? null,
          body.timezone ?? null,
          body.language ?? null,
        ],
      );

      logger.info({ userId: user.userId }, 'User profile upserted');
      res.json({ data: row });
    } catch (err) { next(err); }
  },
);

// ══════════════════════════════════════════════════════════════════════════════
// OWNER PROFILE — company identity, billing info
//
// TRANSITIONAL FIELDS (Phase 2):
//   primary_color, secondary_color, theme_mode — canonical source is now
//   public.user_settings (GET|PUT /api/settings). These columns remain
//   readable/writable here for Phase 1 backward compatibility.
//   Frontend Settings page reads from /api/settings.
//   To be removed from owner_profiles once all consumers migrate.
// ══════════════════════════════════════════════════════════════════════════════

// GET /owner — Fetch the authenticated owner's extended profile
router.get('/owner', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const row = await queryOne(
      `SELECT user_id, company_name, business_type,
              primary_color, secondary_color, theme_mode, logo_url,
              billing_email, billing_address, tax_id,
              created_at, updated_at
       FROM owner_profiles
       WHERE user_id = $1`,
      [user.userId],
    );

    res.json({ data: row || null });
  } catch (err) { next(err); }
});

// PUT /owner — Upsert the authenticated owner's extended profile
router.put('/owner', requireAuth, validateBody(updateOwnerProfileSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateOwnerProfileSchema>;

      const row = await queryOne(
        `INSERT INTO owner_profiles (
           user_id, company_name, business_type,
           primary_color, secondary_color, theme_mode, logo_url,
           billing_email, billing_address, tax_id,
           created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           company_name = COALESCE($2, owner_profiles.company_name),
           business_type = COALESCE($3, owner_profiles.business_type),
           primary_color = COALESCE($4, owner_profiles.primary_color),
           secondary_color = COALESCE($5, owner_profiles.secondary_color),
           theme_mode = COALESCE($6, owner_profiles.theme_mode),
           logo_url = COALESCE($7, owner_profiles.logo_url),
           billing_email = COALESCE($8, owner_profiles.billing_email),
           billing_address = COALESCE($9, owner_profiles.billing_address),
           tax_id = COALESCE($10, owner_profiles.tax_id),
           updated_at = NOW()
         RETURNING *`,
        [
          user.userId,
          body.company_name ?? null,
          body.business_type ?? null,
          body.primary_color ?? null,
          body.secondary_color ?? null,
          body.theme_mode ?? null,
          body.logo_url ?? null,
          body.billing_email ?? null,
          body.billing_address ?? null,
          body.tax_id ?? null,
        ],
      );

      logger.info({ userId: user.userId }, 'Owner profile upserted');
      res.json({ data: row });
    } catch (err) { next(err); }
  },
);

export { router as profileRouter };
