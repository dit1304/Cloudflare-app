-- Migration: Add is_premium column to existing users table
-- Run this if upgrading from v1.0 to v2.0

-- Check if column exists and add if not
-- Note: D1 doesn't support IF NOT EXISTS for columns, so you may need to check manually

-- Add is_premium column (run only if it doesn't exist)
ALTER TABLE users ADD COLUMN is_premium INTEGER DEFAULT 0;

-- Update admin to premium
UPDATE users SET is_premium = 1 WHERE telegram_user_id = '1462157376';

-- Create index for faster premium queries
CREATE INDEX IF NOT EXISTS idx_users_premium ON users(is_premium);
