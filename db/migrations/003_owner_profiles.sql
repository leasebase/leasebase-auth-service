-- Migration: 003_owner_profiles
-- Creates the owner_profiles table in the public schema.
-- Stores owner/landlord-specific profile data: company info, branding, billing.
-- Idempotent: uses IF NOT EXISTS guards.
--
-- Run as leasebase_admin:
--   psql -h <host> -U leasebase_admin -d leasebase -f db/migrations/003_owner_profiles.sql

SET search_path TO public;

CREATE TABLE IF NOT EXISTS owner_profiles (
    user_id UUID PRIMARY KEY,

    company_name TEXT,
    business_type TEXT,

    primary_color TEXT,
    secondary_color TEXT,
    theme_mode TEXT DEFAULT 'system',

    logo_url TEXT,

    billing_email TEXT,
    billing_address TEXT,
    tax_id TEXT,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
