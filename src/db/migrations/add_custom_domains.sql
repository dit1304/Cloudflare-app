-- Migration: Add custom domain support
-- Version: 2.2.0
-- Date: 2024-02-07

-- Create custom_domains table
CREATE TABLE IF NOT EXISTS custom_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    status TEXT DEFAULT 'pending',  -- pending/approved/rejected/active/suspended
    
    -- Request info
    requested_at TEXT DEFAULT (datetime('now')),
    request_note TEXT,
    
    -- Admin decision
    reviewed_by INTEGER,
    reviewed_at TEXT,
    admin_note TEXT,
    
    -- DNS Verification
    verification_code TEXT,
    dns_verified INTEGER DEFAULT 0,
    verified_at TEXT,
    
    -- Activation
    activated_at TEXT,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_custom_domains_user ON custom_domains(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domains(status);
CREATE INDEX IF NOT EXISTS idx_custom_domains_domain ON custom_domains(domain);

-- Note: We track custom domains via domain string in email_address
-- No need to modify emails table structure (backward compatible)
