-- Migration: add_password_hash
ALTER TABLE IF EXISTS flappy_xwing.users ADD COLUMN IF NOT EXISTS password_hash text;
ALTER TABLE IF EXISTS flappy_xwing.admins ADD COLUMN IF NOT EXISTS password_hash text;

-- Also, update the flappy_register_user RPC or drop it if no longer used.
-- We will handle registration in the edge function, so we don't strictly need to modify the RPC
-- unless we want to keep using the RPC for DB insertion (but then we need a password param).
-- Let's update it anyway to accept p_password_hash text.

-- Actually, we'll just insert directly from the Edge Function into the users table using the service_role key,
-- or we can update the RPC to take p_password_hash.
-- For safety, we'll just alter the tables for now.
