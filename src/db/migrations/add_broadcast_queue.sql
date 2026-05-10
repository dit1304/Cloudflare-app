-- Broadcast queue untuk free plan Cloudflare Workers (limit 50 subrequest / invocation)
-- Setiap /broadcast akan insert semua target user ke broadcast_queue,
-- Scheduled handler (cron 1 menit) akan memproses batch demi batch.

CREATE TABLE IF NOT EXISTS broadcast_jobs (
    id TEXT PRIMARY KEY,                 -- broadcast_id (UUID)
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
    message_type TEXT NOT NULL DEFAULT 'text',   -- 'text' | 'photo'
    message_text TEXT NOT NULL,                  -- HTML text atau caption
    photo_file_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',      -- pending | sent | failed
    attempts INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_bq_status ON broadcast_queue(status);
CREATE INDEX IF NOT EXISTS idx_bq_broadcast_id ON broadcast_queue(broadcast_id);
CREATE INDEX IF NOT EXISTS idx_bj_completed ON broadcast_jobs(completed_at);
