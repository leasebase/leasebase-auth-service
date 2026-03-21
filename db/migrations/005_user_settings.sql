-- Migration: 005_user_settings
-- Creates the user_settings table in the public schema.
-- Stores per-user application behavior/presentation settings (theme, branding, defaults).
-- Canonical source for theme_mode, primary_color, secondary_color (previously in owner_profiles).
-- Idempotent: uses IF NOT EXISTS guards.
--
-- Run as leasebase_admin:
--   psql -h <host> -U leasebase_admin -d leasebase -f db/migrations/005_user_settings.sql

SET search_path TO public;

CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID PRIMARY KEY,
    theme_mode TEXT NOT NULL DEFAULT 'system',
    primary_color TEXT,
    secondary_color TEXT,
    default_dashboard TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
