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
  // Phase 3: theme/color fields removed from owner profile writes.
  // Canonical source is user_settings (GET|PUT /api/settings).
  // These fields are still readable in GET for backward compat.
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
//
// Null-clearing contract (Phase 3):
//   - omitted field → no change
//   - provided value → set
//   - provided null → clear (for nullable fields)
router.put('/', requireAuth, validateBody(updateProfileSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateProfileSchema>;

      // Build dynamic SET clauses — only fields present in the body are touched.
      const setClauses: string[] = [];
      const params: unknown[] = [user.userId];
      let idx = 2;

      const fields: Array<[string, unknown]> = [
        ['first_name', body.first_name],
        ['last_name', body.last_name],
        ['phone_number', body.phone_number],
        ['avatar_url', body.avatar_url],
        ['timezone', body.timezone],
        ['language', body.language],
      ];

      for (const [col, val] of fields) {
        if (col in body) {
          setClauses.push(`${col} = $${idx}`);
          params.push(val ?? null);
          idx++;
        }
      }

      let row;
      if (setClauses.length === 0) {
        // No fields to update — just ensure a row exists
        row = await queryOne(
          `INSERT INTO user_profiles (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO NOTHING
           RETURNING *`,
          [user.userId],
        );
        if (!row) {
          row = await queryOne(`SELECT * FROM user_profiles WHERE user_id = $1`, [user.userId]);
        }
      } else {
        setClauses.push('updated_at = NOW()');
        row = await queryOne(
          `INSERT INTO user_profiles (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO UPDATE SET ${setClauses.join(', ')}
           RETURNING *`,
          params,
        );
      }

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
// Phase 3: no longer writes theme_mode/primary_color/secondary_color
// (canonical source is user_settings). Dynamic SET for null-clearing.
router.put('/owner', requireAuth, validateBody(updateOwnerProfileSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateOwnerProfileSchema>;

      const setClauses: string[] = [];
      const params: unknown[] = [user.userId];
      let idx = 2;

      const fields: Array<[string, unknown]> = [
        ['company_name', body.company_name],
        ['business_type', body.business_type],
        ['logo_url', body.logo_url],
        ['billing_email', body.billing_email],
        ['billing_address', body.billing_address],
        ['tax_id', body.tax_id],
      ];

      for (const [col, val] of fields) {
        if (col in body) {
          setClauses.push(`${col} = $${idx}`);
          params.push(val ?? null);
          idx++;
        }
      }

      let row;
      if (setClauses.length === 0) {
        row = await queryOne(
          `INSERT INTO owner_profiles (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO NOTHING
           RETURNING *`,
          [user.userId],
        );
        if (!row) {
          row = await queryOne(`SELECT * FROM owner_profiles WHERE user_id = $1`, [user.userId]);
        }
      } else {
        setClauses.push('updated_at = NOW()');
        row = await queryOne(
          `INSERT INTO owner_profiles (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO UPDATE SET ${setClauses.join(', ')}
           RETURNING *`,
          params,
        );
      }

      logger.info({ userId: user.userId }, 'Owner profile upserted');
      res.json({ data: row });
    } catch (err) { next(err); }
  },
);

export { router as profileRouter };
