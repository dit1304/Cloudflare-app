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

-- Add custom domain support to emails table
ALTER TABLE emails ADD COLUMN domain_id INTEGER;
ALTER TABLE emails ADD COLUMN uses_custom_domain INTEGER DEFAULT 0;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_custom_domains_user ON custom_domains(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domains(status);
CREATE INDEX IF NOT EXISTS idx_custom_domains_domain ON custom_domains(domain);
CREATE INDEX IF NOT EXISTS idx_emails_domain ON emails(domain_id);

-- Add foreign key for emails to custom_domains
-- Note: SQLite doesn't support adding FK to existing table, so this is for reference only
-- ALTER TABLE emails ADD FOREIGN KEY (domain_id) REFERENCES custom_domains(id) ON DELETE SET NULL;
