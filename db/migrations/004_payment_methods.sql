-- Migration: 004_payment_methods
-- Creates the payment_methods table in the public schema.
-- Shared future-proof table for storing user payment methods (card / bank).
-- Idempotent: uses IF NOT EXISTS guards.
--
-- Run as leasebase_admin:
--   psql -h <host> -U leasebase_admin -d leasebase -f db/migrations/004_payment_methods.sql

SET search_path TO public;

CREATE TABLE IF NOT EXISTS payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,

    type TEXT NOT NULL,        -- card / bank
    brand TEXT,
    last4 TEXT,
    expiration TEXT,

    is_default BOOLEAN DEFAULT false,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_methods_user_id ON payment_methods(user_id);
