-- Migration: 006_backfill_user_settings
-- Idempotent backfill: copy theme/color settings from owner_profiles to user_settings
-- for users that have owner_profiles data but no user_settings row.
-- Safe to re-run; INSERT ... ON CONFLICT DO NOTHING.

SET search_path TO public;

INSERT INTO user_settings (user_id, theme_mode, primary_color, secondary_color, created_at, updated_at)
SELECT op.user_id,
       COALESCE(op.theme_mode, 'system'),
       op.primary_color,
       op.secondary_color,
       NOW(), NOW()
FROM owner_profiles op
WHERE NOT EXISTS (
  SELECT 1 FROM user_settings us WHERE us.user_id = op.user_id
)
AND (op.theme_mode IS NOT NULL OR op.primary_color IS NOT NULL OR op.secondary_color IS NOT NULL)
ON CONFLICT (user_id) DO NOTHING;
