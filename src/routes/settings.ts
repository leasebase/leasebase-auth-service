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

// ── Schema ───────────────────────────────────────────────────────────────────

const updateSettingsSchema = z.object({
  theme_mode: z.enum(['light', 'dark', 'system']).optional(),
  primary_color: z.string().max(20).nullable().optional(),
  secondary_color: z.string().max(20).nullable().optional(),
  default_dashboard: z.string().max(100).nullable().optional(),
});

// ══════════════════════════════════════════════════════════════════════════════
// USER SETTINGS — application behavior / presentation
//
// Canonical source for:
//   theme_mode, primary_color, secondary_color, default_dashboard
//
// Note: owner_profiles still has theme_mode/primary_color/secondary_color
// columns for Phase 1 backward compatibility. Those are transitional —
// user_settings is the canonical source going forward.
// ══════════════════════════════════════════════════════════════════════════════

// GET / — Fetch the authenticated user's settings
router.get('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const row = await queryOne(
      `SELECT user_id, theme_mode, primary_color, secondary_color,
              default_dashboard, created_at, updated_at
       FROM user_settings
       WHERE user_id = $1`,
      [user.userId],
    );

    // Return defaults if no row exists yet
    res.json({
      data: row || {
        user_id: user.userId,
        theme_mode: 'system',
        primary_color: null,
        secondary_color: null,
        default_dashboard: null,
      },
    });
  } catch (err) { next(err); }
});

// PUT / — Upsert the authenticated user's settings
// Null-clearing contract: omitted = no change, null = clear, value = set.
router.put('/', requireAuth, validateBody(updateSettingsSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateSettingsSchema>;

      const setClauses: string[] = [];
      const params: unknown[] = [user.userId];
      let idx = 2;

      const fields: Array<[string, unknown]> = [
        ['theme_mode', body.theme_mode],
        ['primary_color', body.primary_color],
        ['secondary_color', body.secondary_color],
        ['default_dashboard', body.default_dashboard],
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
          `INSERT INTO user_settings (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO NOTHING
           RETURNING *`,
          [user.userId],
        );
        if (!row) {
          row = await queryOne(`SELECT * FROM user_settings WHERE user_id = $1`, [user.userId]);
        }
      } else {
        setClauses.push('updated_at = NOW()');
        row = await queryOne(
          `INSERT INTO user_settings (user_id, created_at, updated_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (user_id) DO UPDATE SET ${setClauses.join(', ')}
           RETURNING *`,
          params,
        );
      }

      logger.info({ userId: user.userId }, 'User settings upserted');
      res.json({ data: row });
    } catch (err) { next(err); }
  },
);

export { router as settingsRouter };
