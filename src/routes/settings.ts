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
router.put('/', requireAuth, validateBody(updateSettingsSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const body = req.body as z.infer<typeof updateSettingsSchema>;

      const row = await queryOne(
        `INSERT INTO user_settings (user_id, theme_mode, primary_color, secondary_color, default_dashboard, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           theme_mode = COALESCE($2, user_settings.theme_mode),
           primary_color = COALESCE($3, user_settings.primary_color),
           secondary_color = COALESCE($4, user_settings.secondary_color),
           default_dashboard = COALESCE($5, user_settings.default_dashboard),
           updated_at = NOW()
         RETURNING *`,
        [
          user.userId,
          body.theme_mode ?? null,
          body.primary_color ?? null,
          body.secondary_color ?? null,
          body.default_dashboard ?? null,
        ],
      );

      logger.info({ userId: user.userId }, 'User settings upserted');
      res.json({ data: row });
    } catch (err) { next(err); }
  },
);

export { router as settingsRouter };
