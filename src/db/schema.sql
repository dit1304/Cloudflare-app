-- Temp Email Bot - D1 Database Schema

-- Tabel untuk menyimpan user Telegram
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_user_id TEXT UNIQUE NOT NULL,
    telegram_username TEXT,
    auto_delete_days INTEGER DEFAULT 7,
    language TEXT DEFAULT 'id',
    timezone TEXT DEFAULT 'Asia/Jakarta',
    is_premium INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Tabel untuk menyimpan alamat email temporary
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email_address TEXT UNIQUE NOT NULL,
    local_part TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabel untuk menyimpan pesan email masuk
CREATE TABLE IF NOT EXISTS inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT,
    body TEXT,
    headers TEXT,
    is_read INTEGER DEFAULT 0,
    received_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

-- Tabel untuk menyimpan 2FA secrets
CREATE TABLE IF NOT EXISTS totp_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

-- Tabel untuk blacklist sender
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sender_pattern TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabel untuk custom domains
CREATE TABLE IF NOT EXISTS custom_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    status TEXT DEFAULT 'pending',
    requested_at TEXT DEFAULT (datetime('now')),
    request_note TEXT,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    admin_note TEXT,
    verification_code TEXT,
    dns_verified INTEGER DEFAULT 0,
    verified_at TEXT,
    activated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index untuk query yang sering dipakai
CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id);
CREATE INDEX IF NOT EXISTS idx_emails_address ON emails(email_address);
CREATE INDEX IF NOT EXISTS idx_inbox_email_id ON inbox(email_id);
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_user_id);
CREATE INDEX IF NOT EXISTS idx_totp_user_id ON totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_blacklist_user_id ON blacklist(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_user ON custom_domains(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domains(status);
CREATE INDEX IF NOT EXISTS idx_custom_domains_domain ON custom_domains(domain);

-- Broadcast queue (free plan: 50 subrequest/invocation -> pakai queue + cron)
CREATE TABLE IF NOT EXISTS broadcast_jobs (
    id TEXT PRIMARY KEY,
    admin_chat_id TEXT NOT NULL,
    status_message_id INTEGER,
    total_users INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS broadcast_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    broadcast_id TEXT NOT NULL,
    target_chat_id TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'text',
    message_text TEXT NOT NULL,
    photo_file_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_bq_status ON broadcast_queue(status);
CREATE INDEX IF NOT EXISTS idx_bq_broadcast_id ON broadcast_queue(broadcast_id);
CREATE INDEX IF NOT EXISTS idx_bj_completed ON broadcast_jobs(completed_at);
