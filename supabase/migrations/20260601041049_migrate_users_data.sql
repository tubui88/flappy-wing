-- Migration: migrate_users_data
-- Copy encrypted_password from auth.users to flappy_xwing.users and flappy_xwing.admins

-- 1. Migrate admins
UPDATE flappy_xwing.admins a
SET password_hash = au.encrypted_password
FROM auth.users au
WHERE a.email = au.email;

-- 2. Migrate existing users (if any exist in auth.users)
UPDATE flappy_xwing.users u
SET password_hash = au.encrypted_password
FROM auth.users au
WHERE u.email = au.email;

-- Note: Regular users who previously registered without a password 
-- will have a NULL password_hash. They will need to set a password 
-- upon their next login or re-registration.
