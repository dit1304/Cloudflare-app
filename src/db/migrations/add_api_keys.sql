-- API keys untuk akses REST API (/api/v1)
-- Key asli hanya ditampilkan sekali saat dibuat; yang disimpan hanya SHA-256 hash.
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    rate_limit_per_min INTEGER DEFAULT 60,
    created_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

-- Sliding window rate limit per API key (1 baris per key per menit)
CREATE TABLE IF NOT EXISTS api_rate_limits (
    key_id INTEGER PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);
